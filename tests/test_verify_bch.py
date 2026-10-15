#!/usr/bin/env python3
"""
End-to-end tests for verify_pool.py in Bitcoin Cash mode.

Each test starts a small fake stratum pool on this machine, then runs the real
verify_pool.py against it and checks the verdict:

  honest pool (plain TCP and TLS)     -> PASS
  pool pays itself                    -> FAIL
  pool pays itself but writes your
  address as text in the coinbase     -> FAIL (not fooled)
  TLS cert for the wrong hostname     -> connection refused
  BCH mode with no address            -> refuses to run

TLS tests need the `openssl` command; they are skipped if it's missing.

Run:  python3 -m unittest discover -s tests -v
"""

import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "verify_pool.py")
sys.path.insert(0, os.path.join(HERE, ".."))
import verify_pool as vp  # noqa: E402

# CashAddr spec example, and an unrelated "pool" key hash
USER_CASH = "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
USER_LEGACY = "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu"
USER_HASH = "76a04053bda0a88bda5177b86a15c3b29f559873"
POOL_HASH = "11" * 20
REWARD = 312_646_620


def p2pkh(h):
    return bytes.fromhex("76a914" + h + "88ac")


def output(value, script):
    return value.to_bytes(8, "little") + bytes([len(script)]) + script


def build_coinbase(mode, username=None):
    """Return (coinb1_hex, coinb2_hex) for a BCH-style coinbase (no SegWit)."""
    tag = b"/TestPool/"
    extranonce_len = 4 + 8
    height = bytes([0x03]) + (972699).to_bytes(3, "little")
    script_len = len(height) + extranonce_len + len(tag)
    coinb1 = (bytes.fromhex("01000000") + b"\x01" + b"\x00" * 32 + b"\xff" * 4
              + bytes([script_len]) + height)

    if mode == "honest":
        outs = [output(REWARD, p2pkh(USER_HASH))]
    elif mode == "pays_username":
        # Pay whatever address the miner logged in with, like a real solo pool
        _, h, _ = vp.cashaddr_decode(username.split(".")[0])
        outs = [output(REWARD, p2pkh(h))]
    elif mode == "pays_pool":
        outs = [output(REWARD, p2pkh(POOL_HASH))]
    elif mode == "ascii_trick":
        text = USER_CASH.encode()
        outs = [output(REWARD, p2pkh(POOL_HASH)),
                output(0, b"\x6a" + bytes([len(text)]) + text)]
    else:
        raise ValueError(mode)

    coinb2 = (tag + b"\xff" * 4 + bytes([len(outs)]) + b"".join(outs)
              + b"\x00" * 4)
    return coinb1.hex(), coinb2.hex()


class FakePool:
    def __init__(self, mode, tls_context=None, auth_delay=0):
        self.mode = mode
        self.tls_context = tls_context
        self.auth_delay = auth_delay
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(8)
        self.port = self.server.getsockname()[1]
        self.counter = 0
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            if self.tls_context:
                conn = self.tls_context.wrap_socket(conn, server_side=True)
            buf = b""
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    msg = json.loads(line)
                    if msg["method"] == "mining.subscribe":
                        self.counter += 1
                        en1 = (0xa7a7cb6a + self.counter).to_bytes(4, "big").hex()
                        reply = {"id": msg["id"], "result": [[["mining.notify", "1"]], en1, 8],
                                 "error": None}
                        conn.sendall((json.dumps(reply) + "\n").encode())
                    elif msg["method"] == "mining.authorize":
                        if self.auth_delay:
                            time.sleep(self.auth_delay)  # e.g. a pool checking a new address
                        coinb1, coinb2 = build_coinbase(self.mode, msg["params"][0])
                        replies = [
                            {"id": msg["id"], "result": True, "error": None},
                            {"id": None, "method": "mining.set_difficulty", "params": [1024]},
                            {"id": None, "method": "mining.notify",
                             "params": ["job1", "00" * 32, coinb1, coinb2, [],
                                        "20000000", "18034379", "6700f000", True]},
                        ]
                        conn.sendall("".join(json.dumps(r) + "\n" for r in replies).encode())
        except (OSError, ValueError, ssl.SSLError):
            pass
        finally:
            conn.close()

    def close(self):
        self.server.close()


def run_verifier(*args, env=None):
    result = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True,
                            text=True, timeout=60, env=env)
    return result.returncode, result.stdout + result.stderr


class TestVerifyBCH(unittest.TestCase):

    def run_against(self, mode, address=USER_CASH, extra=()):
        pool = FakePool(mode)
        try:
            return run_verifier("127.0.0.1", str(pool.port), address, *extra,
                                "--timeout", "5", "--retries", "0")
        finally:
            pool.close()

    def test_honest_pool_passes_with_cashaddr(self):
        code, out = self.run_against("honest")
        self.assertEqual(code, 0, out)
        self.assertIn("VERIFICATION PASSED", out)
        self.assertIn("3.12646620 BCH", out)
        self.assertIn("Coin:    BCH", out)
        self.assertIn(USER_LEGACY, out)

    def test_honest_pool_passes_without_prefix(self):
        code, out = self.run_against("honest", address=USER_CASH.split(":")[1])
        self.assertEqual(code, 0, out)

    def test_honest_pool_passes_with_legacy_and_coin_flag(self):
        code, out = self.run_against("honest", address=USER_LEGACY, extra=("--coin", "bch"))
        self.assertEqual(code, 0, out)
        self.assertIn("BCH", out)

    def test_pool_paying_itself_fails(self):
        code, out = self.run_against("pays_pool")
        self.assertEqual(code, 1, out)
        self.assertIn("ADDRESS NOT FOUND", out)

    def test_address_as_text_does_not_fool_it(self):
        code, out = self.run_against("ascii_trick")
        self.assertEqual(code, 1, out)
        self.assertIn("ADDRESS NOT FOUND", out)

    def test_bch_mode_refuses_without_address(self):
        code, out = run_verifier("127.0.0.1", "1", "--coin", "bch")
        self.assertEqual(code, 1)
        self.assertIn("needs YOUR address", out)

    def test_json_summary(self):
        code, out = self.run_against("honest", extra=("--json",))
        self.assertEqual(code, 0, out)
        report = json.loads(out[out.index("{"):out.rindex("}") + 1])
        self.assertEqual(report["result"], "passed")
        self.assertEqual(report["coin"], "BCH")
        self.assertEqual(report["paying_outputs"], 1)
        self.assertEqual(report["outputs"][0]["percent"], 100.0)
        self.assertEqual(report["outputs"][0]["address"], USER_CASH)
        self.assertEqual(report["block_height"], 972699)

    def test_json_summary_on_failure(self):
        code, out = self.run_against("pays_pool", extra=("--json",))
        self.assertEqual(code, 1, out)
        report = json.loads(out[out.index("{"):out.rindex("}") + 1])
        self.assertEqual(report["result"], "address_not_found")

    def test_random_address_is_the_one_paid(self):
        pool = FakePool("pays_username")
        try:
            code, out = run_verifier("127.0.0.1", str(pool.port), "--coin", "bch", "--random-address",
                                     "--json", "--timeout", "5", "--retries", "0")
        finally:
            pool.close()
        self.assertEqual(code, 0, out)
        report = json.loads(out[out.index("{"):out.rindex("}") + 1])
        self.assertEqual(report["result"], "passed")
        self.assertNotEqual(report["address"], USER_CASH)
        self.assertEqual(report["outputs"][0]["address"], report["address"])

    def test_random_address_differs_each_run(self):
        self.assertNotEqual(vp.generate_random_bch_address(), vp.generate_random_bch_address())

    def test_slow_login_reply_still_passes(self):
        pool = FakePool("honest", auth_delay=3)
        try:
            code, out = run_verifier("127.0.0.1", str(pool.port), USER_CASH,
                                     "--timeout", "5", "--retries", "0")
        finally:
            pool.close()
        self.assertEqual(code, 0, out)
        self.assertIn("Worker authorized", out)

    def test_btc_address_rejected_in_bch_mode(self):
        code, out = run_verifier("127.0.0.1", "1", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                                 "--coin", "bch")
        self.assertEqual(code, 1)
        self.assertIn("not Bitcoin Cash", out)


@unittest.skipUnless(shutil.which("openssl"), "openssl command not available")
class TestVerifyBCHOverTLS(unittest.TestCase):
    """A throwaway certificate authority signs a cert for 'localhost'. The
    verifier trusts that CA (via SSL_CERT_FILE) exactly as it would trust a
    real public CA such as Let's Encrypt."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        t = lambda name: os.path.join(cls.tmp, name)  # noqa: E731
        q = {"check": True, "capture_output": True}
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", t("ca.key"), "-out", t("ca.crt"), "-subj", "/CN=Test CA",
                        "-addext", "basicConstraints=critical,CA:TRUE",
                        "-addext", "keyUsage=critical,keyCertSign,cRLSign"], **q)
        subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", t("srv.key"),
                        "-out", t("srv.csr"), "-subj", "/CN=localhost"], **q)
        with open(t("ext.cnf"), "w") as f:
            f.write("subjectAltName=DNS:localhost\n"
                    "basicConstraints=CA:FALSE\n"
                    "keyUsage=critical,digitalSignature,keyEncipherment\n"
                    "extendedKeyUsage=serverAuth\n"
                    "authorityKeyIdentifier=keyid\n")
        subprocess.run(["openssl", "x509", "-req", "-in", t("srv.csr"), "-CA", t("ca.crt"),
                        "-CAkey", t("ca.key"), "-CAcreateserial", "-days", "1",
                        "-extfile", t("ext.cnf"), "-out", t("srv.crt")], **q)
        cls.server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server_ctx.load_cert_chain(t("srv.crt"), t("srv.key"))
        cls.env = dict(os.environ, SSL_CERT_FILE=t("ca.crt"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_honest_pool_passes_over_tls(self):
        pool = FakePool("honest", tls_context=self.server_ctx)
        try:
            code, out = run_verifier("localhost", str(pool.port), USER_CASH, "--tls",
                                     "--timeout", "5", "--retries", "0", env=self.env)
        finally:
            pool.close()
        self.assertEqual(code, 0, out)
        self.assertIn("TLS (encrypted, certificate checked)", out)
        self.assertIn("VERIFICATION PASSED", out)

    def test_wrong_hostname_certificate_rejected(self):
        # The cert is for 'localhost' but we connect as '127.0.0.1'
        pool = FakePool("honest", tls_context=self.server_ctx)
        try:
            code, out = run_verifier("127.0.0.1", str(pool.port), USER_CASH, "--tls",
                                     "--timeout", "5", "--retries", "0", env=self.env)
        finally:
            pool.close()
        self.assertEqual(code, 1, out)
        self.assertIn("certificate check failed", out)


if __name__ == "__main__":
    unittest.main()
