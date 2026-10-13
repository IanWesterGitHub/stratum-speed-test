#!/usr/bin/env python3
"""
CashAddr tests for verify_pool.py (Bitcoin Cash support).

The legacy <-> CashAddr pairs below are the examples published in the
CashAddr specification:
  https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md

Each pair encodes the same 20-byte hash, so decoding either form must give
identical results. This proves the CashAddr decoder can't quietly map your
address to someone else's.

Run:  python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import verify_pool as vp  # noqa: E402

SPEC_VECTORS = [
    # (legacy, cashaddr, type)
    ("1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu", "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "P2PKH"),
    ("1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR", "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy", "P2PKH"),
    ("16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb", "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r", "P2PKH"),
    ("3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC", "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq", "P2SH"),
    ("3LDsS579y7sruadqu11beEJoTjdFiFCdX4", "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e", "P2SH"),
    ("31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw", "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37", "P2SH"),
]


class TestCashAddr(unittest.TestCase):

    def setUp(self):
        vp.COIN = "BCH"

    def tearDown(self):
        vp.COIN = "BTC"

    def test_decode_matches_legacy_hash(self):
        for legacy, cash, kind in SPEC_VECTORS:
            with self.subTest(cash=cash):
                addr_type, h, err = vp.cashaddr_decode(cash)
                self.assertEqual(err, "")
                self.assertEqual(addr_type, kind)
                self.assertEqual(h, vp.base58_decode(legacy))

    def test_prefix_is_optional(self):
        for _, cash, _ in SPEC_VECTORS:
            with self.subTest(cash=cash):
                self.assertEqual(vp.cashaddr_decode(cash), vp.cashaddr_decode(cash.split(":")[1]))

    def test_upper_case_accepted(self):
        _, cash, _ = SPEC_VECTORS[0]
        self.assertEqual(vp.cashaddr_decode(cash.upper()), vp.cashaddr_decode(cash))

    def test_round_trip_encode(self):
        for legacy, cash, kind in SPEC_VECTORS:
            with self.subTest(cash=cash):
                _, h, _ = vp.cashaddr_decode(cash)
                self.assertEqual(vp.cashaddr_encode(h, kind), cash)
                self.assertEqual(vp.legacy_address(h, kind), legacy)

    def test_typo_rejected(self):
        _, cash, _ = SPEC_VECTORS[0]
        # Change one character: the checksum must catch it
        bad = cash[:-5] + ("q" if cash[-5] != "q" else "p") + cash[-4:]
        addr_type, h, err = vp.cashaddr_decode(bad)
        self.assertIsNone(h)
        self.assertIn("checksum", err)

    def test_mixed_case_rejected(self):
        _, cash, _ = SPEC_VECTORS[0]
        mixed = cash[:20] + cash[20:].upper()
        self.assertIsNone(vp.cashaddr_decode(mixed)[1])

    def test_wrong_prefix_rejected(self):
        self.assertIsNone(vp.cashaddr_decode("bchtest:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a")[1])

    def test_validate_in_bch_mode(self):
        for legacy, cash, _ in SPEC_VECTORS:
            with self.subTest(cash=cash):
                self.assertTrue(vp.validate_bitcoin_address(cash)[0])
                self.assertTrue(vp.validate_bitcoin_address(cash.split(":")[1])[0])
                self.assertTrue(vp.validate_bitcoin_address(legacy)[0])

    def test_btc_segwit_rejected_in_bch_mode(self):
        ok, err = vp.validate_bitcoin_address("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
        self.assertFalse(ok)
        self.assertIn("not Bitcoin Cash", err)

    def test_cashaddr_needs_bch_mode(self):
        vp.COIN = "BTC"
        ok, err = vp.validate_bitcoin_address(SPEC_VECTORS[0][1])
        self.assertFalse(ok)
        self.assertIn("--coin bch", err)


if __name__ == "__main__":
    unittest.main()
