"""Unit & cross-language interop tests for paxiom_receipts.proofs (v0.4.0)."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import paxiom_receipts as pr

ROOT_V0 = Path(__file__).resolve().parents[2]
FIXTURES = ROOT_V0 / "test" / "fixtures"
ETH_FIXTURE = json.loads((FIXTURES / "eth-mainnet-usdc-eip1186.json").read_text(encoding="utf-8"))
BASE_FIXTURE = json.loads((FIXTURES / "base-mainnet-usdc-receipt-proof.json").read_text(encoding="utf-8"))
ZERO_BLOOM = "0x" + ("00" * 256)


def _make_transfer_log(token: str, frm: str, to: str, amount: int) -> dict:
    pad = lambda a: "0x" + ("0" * 24) + a.lower().removeprefix("0x")
    return {
        "address": token,
        "topics": [pr.ERC20_TRANSFER_TOPIC0, pad(frm), pad(to)],
        "data": f"0x{amount:064x}",
    }


class TestProofsModule(unittest.TestCase):
    def test_keccak256_vectors_and_rate_boundaries(self) -> None:
        self.assertEqual(
            pr.keccak256_hex(b""),
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(
            pr.keccak256_hex(b"abc"),
            "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )
        self.assertEqual(
            pr.keccak256_hex(b"Transfer(address,address,uint256)"),
            pr.ERC20_TRANSFER_TOPIC0,
        )
        self.assertEqual(pr.keccak256_hex(b"\x80"), pr.EMPTY_TRIE_ROOT_HEX)
        # 135, 136, 137-byte Keccak-f[1600] rate=136 boundaries
        self.assertEqual(
            pr.keccak256_hex(b"a" * 135),
            "0x34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446",
        )
        self.assertEqual(
            pr.keccak256_hex(b"a" * 136),
            "0xa6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e",
        )
        self.assertEqual(
            pr.keccak256_hex(b"a" * 137),
            "0xd869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39",
        )

    def test_canonical_rlp_and_malleability_rejection(self) -> None:
        self.assertEqual(pr.rlp_encode(0).hex(), "80")
        self.assertEqual(pr.rlp_encode(15).hex(), "0f")
        self.assertEqual(pr.rlp_encode(1024).hex(), "820400")
        set_three = [[], [[]], [[], [[]]]]
        self.assertEqual(pr.rlp_encode(set_three).hex(), "c7c0c1c0c3c0c1c0")
        self.assertEqual(pr.rlp_decode("0xc7c0c1c0c3c0c1c0"), set_three)

        with self.assertRaisesRegex(ValueError, "Non-canonical RLP"):
            pr.rlp_decode("0x817f")
        with self.assertRaisesRegex(ValueError, "length <= 55"):
            pr.rlp_decode("0xb803616263")
        with self.assertRaisesRegex(ValueError, "leading zero"):
            pr.rlp_decode("0xb90038" + ("61" * 56))
        with self.assertRaisesRegex(ValueError, "Trailing"):
            pr.rlp_decode("0x8000")
        with self.assertRaisesRegex(ValueError, "maximum depth"):
            pr.rlp_decode("0x" + ("c1" * 66) + "c0")

    def test_mpt_inline_nodes_and_exclusion_proofs(self) -> None:
        entries = [
            {"key": "0x11223300", "value": "0x01"},
            {"key": "0x11223301", "value": "0x02"},
            {"key": "0x11224400", "value": "0x" + ("aa" * 40)},
            {"key": "0x99887766", "value": "0x" + ("bb" * 48)},
        ]
        for e in entries:
            built = pr.build_mpt_proof(entries, e["key"])
            res = pr.verify_mpt_proof(
                root_hash=built["rootHash"],
                key=e["key"],
                proof=built["proof"],
                expected_value=e["value"],
            )
            self.assertTrue(res["ok"], res["reason"])
            self.assertEqual("0x" + res["value"].hex(), e["value"])

        for absent in ("0x55000000", "0x11230000", "0x99887799"):
            built = pr.build_mpt_proof(entries, absent)
            self.assertIsNone(built["value"])
            res = pr.verify_mpt_proof(
                root_hash=built["rootHash"],
                key=absent,
                proof=built["proof"],
                expected_value=None,
            )
            self.assertTrue(res["ok"], res["reason"])
            self.assertEqual(res["code"], "verified_absent")

    def test_real_ethereum_mainnet_eip1186_usdc_proof(self) -> None:
        res = pr.verify_eip1186_proof(
            state_root=ETH_FIXTURE["stateRoot"],
            proof=ETH_FIXTURE["proof"],
            expected_storage={
                "0x0": ETH_FIXTURE["proof"]["storageProof"][0]["value"],
                "0xdeadbeef": 0,
            },
        )
        self.assertTrue(res["ok"], res["reason"])
        self.assertEqual(len(res["storage"]), 2)
        self.assertEqual(res["storage"][1]["value"], 0)

    def test_real_base_mainnet_receipt_proof_and_arbiter_upgrade(self) -> None:
        seller_kp = pr.generate_receipt_keypair("py-seller-01")
        witness_kp = pr.generate_receipt_keypair("py-witness-01")
        out = {"ok": True, "source": "base-mainnet"}

        issued = pr.issue_receipt(
            private_key=seller_kp["privateKeyPem"],
            issuer={"name": "Base Py Seller", "keyId": seller_kp["keyId"], "payTo": BASE_FIXTURE["payTo"]},
            service={"name": "Feed", "resource": "https://seller.example/v1/feed", "method": "GET"},
            request={"method": "GET", "resource": "https://seller.example/v1/feed", "body": ""},
            payment={
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": "USDC",
                "amountAtomic": BASE_FIXTURE["amountAtomic"],
                "amountDisplay": "4329.679740",
                "payer": BASE_FIXTURE["payer"],
                "payTo": BASE_FIXTURE["payTo"],
                "settlement": {
                    "status": "claimed_not_checked",
                    "transactionHash": BASE_FIXTURE["settlementProof"]["transactionHash"],
                },
            },
            output=out,
        )
        receipt = issued["receipt"]

        root_att = pr.issue_root_attestation(
            private_key=witness_kp["privateKeyPem"],
            network="base",
            block_number=BASE_FIXTURE["blockNumber"],
            block_hash=BASE_FIXTURE["blockHash"],
            state_root=BASE_FIXTURE["stateRoot"],
            receipts_root=BASE_FIXTURE["receiptsRoot"],
            finality_tier="l2-sequencer-attested",
            issued_at="2026-11-18T18:00:00Z",
            expires_at="2026-11-19T18:00:00Z",
            attester={"name": "Py Root Witness", "keyId": witness_kp["keyId"]},
        )

        verdict = pr.verify_receipt(
            receipt,
            output=out,
            expected_issuer_public_keys=[seller_kp["publicKey"]],
            expected_pay_to=BASE_FIXTURE["payTo"],
            settlement_proof=BASE_FIXTURE["settlementProof"],
            root_attestation=root_att,
            trusted_root_public_keys=[witness_kp["publicKey"]],
            now="2026-11-18T19:00:00Z",
        )
        self.assertTrue(verdict["valid"], verdict["summary"])
        self.assertEqual(verdict["trustState"], "verified")
        self.assertEqual(verdict["checks"]["settlement"], "verified_settled")
        self.assertEqual(verdict["checks"]["proof"], "verified")

        # Strict Gate 2 Arbiter with allow_unchecked_settlement_claim=False -> CAPTURE
        proof_hdr = base64.urlsafe_b64encode(
            json.dumps({**BASE_FIXTURE["settlementProof"], "rootAttestation": root_att}).encode("utf-8")
        ).decode("ascii").rstrip("=")

        arb = pr.evaluate_delivery_arbiter(
            {
                "origin": "https://seller.example",
                "scheme": "exact",
                "request": {"url": "https://seller.example/v1/feed", "method": "GET", "body": ""},
                "response": {
                    "status": 200,
                    "headers": {
                        "payment-receipt": issued["receiptHeader"],
                        "payment-settlement-proof": proof_hdr,
                    },
                },
                "body": json.dumps(out),
            },
            expected_issuer_public_keys=[seller_kp["publicKey"]],
            expected_pay_to=BASE_FIXTURE["payTo"],
            trusted_root_public_keys=[witness_kp["publicKey"]],
            allow_unchecked_settlement_claim=False,
            now_ms=1795028400000,  # 2026-11-18T19:00:00Z
        )
        self.assertEqual(arb["action"], "CAPTURE", arb["reason"])

        # Cross-verify Python-issued paxiom.root.v0 + MPT proof inside Node WebCrypto SDK!
        node_code = """
import crypto from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = crypto.webcrypto;
import * as webSdk from './src/web.mjs';
const input = JSON.parse(process.argv[1]);
const res = await webSdk.verifyReceipt(input.receipt, {
  output: input.output,
  settlementProof: input.settlementProof,
  rootAttestation: input.rootAttestation,
  trustedRootPublicKeys: input.trustedRootPublicKeys,
  now: Date.parse('2026-11-18T19:00:00Z')
});
if (!res.valid || res.trustState !== 'verified') {
  console.error(res);
  process.exit(1);
}
"""
        proc = subprocess.run(
            [
                "node",
                "--input-type=module",
                "-e",
                node_code,
                json.dumps({
                    "receipt": receipt,
                    "output": out,
                    "settlementProof": BASE_FIXTURE["settlementProof"],
                    "rootAttestation": root_att,
                    "trustedRootPublicKeys": [witness_kp["publicKey"]],
                }),
            ],
            cwd=str(ROOT_V0),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_circle_arc_and_adversarial_rejections(self) -> None:
        kp = pr.generate_receipt_keypair("arc-py-01")
        payer = "0x35a9dd3fae03ae16dd93a67d185569ec0aa3e6c3"
        pay_to = "0x9786f5532ab7d7556cda53e3f6c2d937c9b87bc4"
        arc_usdc = pr.CANONICAL_USDC_BY_NETWORK["eip155:5042"]
        receipts = [
            {
                "type": "0x2",
                "status": "0x1",
                "cumulativeGasUsed": "0x5208",
                "logsBloom": ZERO_BLOOM,
                "transactionIndex": 0,
                "transactionHash": "0x" + ("11" * 32),
                "blockNumber": 100,
                "logs": [_make_transfer_log(arc_usdc, payer, pay_to, 25_000)],
            },
            {
                "type": "0x2",
                "status": "0x0",
                "cumulativeGasUsed": "0xa410",
                "logsBloom": ZERO_BLOOM,
                "transactionIndex": 1,
                "transactionHash": "0x" + ("22" * 32),
                "blockNumber": 100,
                "logs": [_make_transfer_log(arc_usdc, payer, pay_to, 25_000)],
            },
        ]
        p_ok = pr.build_receipt_trie_proof(receipts, 0, network="arc")
        p_rev = pr.build_receipt_trie_proof(receipts, 1, network="arc")
        roots = [{"network": "eip155:5042", "blockNumber": 100, "receiptsRoot": p_ok["receiptsRoot"]}]
        out = {"arc": True}

        r_ok = pr.issue_receipt(
            private_key=kp["privateKeyPem"],
            issuer={"name": "Arc", "keyId": kp["keyId"], "payTo": pay_to},
            service={"name": "S", "resource": "/s", "method": "POST"},
            request={"method": "POST", "resource": "/s", "body": ""},
            payment={
                "scheme": "batch-settlement",
                "network": "arc",
                "asset": "USDC",
                "amountAtomic": "25000",
                "amountDisplay": "0.025",
                "payer": payer,
                "payTo": pay_to,
                "settlement": {"status": "claimed_not_checked", "transactionHash": "0x" + ("11" * 32)},
            },
            output=out,
        )["receipt"]
        res_ok = pr.verify_receipt(r_ok, output=out, settlement_proof=p_ok, trusted_roots=roots)
        self.assertTrue(res_ok["valid"], res_ok["summary"])

        r_rev = pr.issue_receipt(
            private_key=kp["privateKeyPem"],
            issuer={"name": "Arc", "keyId": kp["keyId"], "payTo": pay_to},
            service={"name": "S", "resource": "/s", "method": "POST"},
            request={"method": "POST", "resource": "/s", "body": ""},
            payment={
                "scheme": "batch-settlement",
                "network": "arc",
                "asset": "USDC",
                "amountAtomic": "25000",
                "amountDisplay": "0.025",
                "payer": payer,
                "payTo": pay_to,
                "settlement": {"status": "claimed_not_checked", "transactionHash": "0x" + ("22" * 32)},
            },
            output=out,
        )["receipt"]
        res_rev = pr.verify_receipt(r_rev, output=out, settlement_proof=p_rev, trusted_roots=roots)
        self.assertFalse(res_rev["valid"])
        self.assertEqual(res_rev["trustState"], "settlement_failed")


if __name__ == "__main__":
    unittest.main()
