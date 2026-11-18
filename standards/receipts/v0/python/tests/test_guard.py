import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import json
import time
import unittest

from paxiom_receipts import (
    MemorySpendLedger,
    evaluate_delivery_arbiter,
    evaluate_pre_sign_policy,
    generate_receipt_keypair,
    issue_receipt,
)

TRUSTED_OP = "0x1111111111111111111111111111111111111111"
SELLER_PAY_TO = "0x2222222222222222222222222222222222222222"
INFO_HASH = "0x" + "cd" * 32


class TestBuyerGuard(unittest.TestCase):
    def test_pre_sign_policy_and_escrow_upgrade(self) -> None:
        now_ms = int(time.time() * 1000)
        now_sec = now_ms // 1000
        ledger = MemorySpendLedger()
        policy = {
            "maxPerCallAtomic": 500_000,
            "maxPerOriginWindowAtomic": 800_000,
            "maxSessionAtomic": 1_000_000,
            "maxUnescrowedExactAtomic": 10_000,
            "trustedOperators": [TRUSTED_OP],
            "pinnedPayToByOrigin": {"https://api.seller.example": SELLER_PAY_TO},
            "maxAllowedFeeBps": 200,
        }

        deny_exact = evaluate_pre_sign_policy(
            {
                "url": "https://api.seller.example/v1/run",
                "nowMs": now_ms,
                "challenge": {"scheme": "exact", "network": "base", "amount": "250000", "payTo": SELLER_PAY_TO},
            },
            policy,
            ledger,
        )
        self.assertFalse(deny_exact["allow"])
        self.assertEqual(deny_exact["code"], "escrow_required_above_microcap")

        allow_escrow = evaluate_pre_sign_policy(
            {
                "url": "https://api.seller.example/v1/run",
                "nowMs": now_ms,
                "challenge": {
                    "accepts": [
                        {"scheme": "exact", "network": "base", "amount": "250000", "payTo": SELLER_PAY_TO},
                        {
                            "scheme": "auth-capture",
                            "network": "base",
                            "amount": "250000",
                            "payTo": SELLER_PAY_TO,
                            "extra": {
                                "operator": TRUSTED_OP,
                                "minFeeBps": 0,
                                "maxFeeBps": 100,
                                "authorizationExpiry": now_sec + 600,
                                "paymentInfoHash": INFO_HASH,
                            },
                        },
                    ]
                },
            },
            policy,
            ledger,
        )
        self.assertTrue(allow_escrow["allow"])
        self.assertEqual(allow_escrow["challenge"]["scheme"], "auth-capture")
        self.assertEqual(allow_escrow["reservedAtomic"], 250_000)

    def test_delivery_arbiter_capture_void_and_replay(self) -> None:
        kp = generate_receipt_keypair("py-guard-key-1")
        ledger = MemorySpendLedger()
        now_ms = int(time.time() * 1000)
        challenge = {
            "scheme": "auth-capture",
            "network": "eip155:8453",
            "amountAtomic": 100_000,
            "payTo": SELLER_PAY_TO,
            "authCapture": {"operator": TRUSTED_OP, "paymentInfoHash": INFO_HASH},
        }
        rsv = ledger.reserve(origin="https://api.seller.example", amount_atomic=100_000, scheme="auth-capture", now_ms=now_ms)
        good_out = {"items": [1, 2, 3]}
        issued = issue_receipt(
            private_key=kp["privateKeyPem"],
            issuer={"name": "Seller", "keyId": kp["keyId"], "payTo": SELLER_PAY_TO},
            service={"name": "Seller", "resource": "https://api.seller.example/v1/items?page=1", "method": "GET"},
            request={"method": "GET", "resource": "https://api.seller.example/v1/items?page=1", "body": ""},
            payment={
                "scheme": "auth-capture",
                "network": "eip155:8453",
                "asset": "USDC",
                "amountAtomic": "100000",
                "payTo": SELLER_PAY_TO,
                "settlement": {"status": "verify_only", "transactionHash": None},
            },
            output=good_out,
        )

        dec_ok = evaluate_delivery_arbiter(
            {
                "origin": "https://api.seller.example",
                "reservationId": rsv,
                "challenge": challenge,
                "request": {"url": "https://api.seller.example/v1/items?page=1", "method": "GET"},
                "response": {"status": 200, "headers": {"payment-receipt": issued["receiptHeader"]}},
                "body": json.dumps(good_out),
            },
            ledger=ledger,
            expected_issuer_public_keys=[kp["publicKey"]],
            validate_content=lambda out, _ctx: bool(out.get("items")),
            now_ms=now_ms,
        )
        self.assertEqual(dec_ok["action"], "CAPTURE")
        self.assertEqual(ledger.snapshot(now_ms)["committedSessionAtomic"], 100_000)

        # Replay fails closed
        dec_replay = evaluate_delivery_arbiter(
            {
                "origin": "https://api.seller.example",
                "challenge": challenge,
                "request": {"url": "https://api.seller.example/v1/items?page=1", "method": "GET"},
                "response": {"status": 200, "headers": {"payment-receipt": issued["receiptHeader"]}},
                "body": json.dumps(good_out),
            },
            ledger=ledger,
            expected_issuer_public_keys=[kp["publicKey"]],
            now_ms=now_ms,
        )
        self.assertEqual(dec_replay["action"], "VOID")
        self.assertEqual(dec_replay["reasonCode"], "replayed_receipt")

        # Bogus signed response produces non-repudiable fraud evidence
        bogus_out = {"items": []}
        bogus_issued = issue_receipt(
            private_key=kp["privateKeyPem"],
            issuer={"name": "Seller", "keyId": kp["keyId"], "payTo": SELLER_PAY_TO},
            service={"name": "Seller", "resource": "https://api.seller.example/v1/items?page=2", "method": "GET"},
            request={"method": "GET", "resource": "https://api.seller.example/v1/items?page=2", "body": ""},
            payment={
                "scheme": "auth-capture",
                "network": "eip155:8453",
                "asset": "USDC",
                "amountAtomic": "100000",
                "payTo": SELLER_PAY_TO,
                "settlement": {"status": "verify_only", "transactionHash": None},
            },
            output=bogus_out,
        )
        dec_bogus = evaluate_delivery_arbiter(
            {
                "origin": "https://api.seller.example",
                "challenge": challenge,
                "request": {"url": "https://api.seller.example/v1/items?page=2", "method": "GET"},
                "response": {"status": 200, "headers": {"payment-receipt": bogus_issued["receiptHeader"]}},
                "body": json.dumps(bogus_out),
            },
            ledger=ledger,
            expected_issuer_public_keys=[kp["publicKey"]],
            validate_content=lambda out, _ctx: {"ok": False, "reason": "empty items"} if not out.get("items") else True,
            now_ms=now_ms,
        )
        self.assertEqual(dec_bogus["action"], "VOID")
        self.assertEqual(dec_bogus["reasonCode"], "content_rejected")
        self.assertTrue(dec_bogus["fraudEvidence"]["nonRepudiable"])
        self.assertEqual(dec_bogus["fraudEvidence"]["issuerKeyId"], kp["keyId"])

    def test_allowed_assets_pay_to_and_payment_binding(self) -> None:
        usdc = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
        bad_asset = evaluate_pre_sign_policy(
            {
                "url": "https://api.seller.example/v1/q",
                "challenge": {"scheme": "exact", "network": "base", "asset": "0xdead", "amount": "1000", "payTo": SELLER_PAY_TO},
            },
            {"allowedAssets": [usdc], "allowedPayTo": [SELLER_PAY_TO]},
        )
        self.assertFalse(bad_asset["allow"])
        self.assertEqual(bad_asset["code"], "asset_not_allowed")

        bad_pay_to = evaluate_pre_sign_policy(
            {
                "url": "https://api.seller.example/v1/q",
                "challenge": {"scheme": "exact", "network": "base", "asset": usdc, "amount": "1000", "payTo": TRUSTED_OP},
            },
            {"allowedAssets": [usdc], "allowedPayTo": [SELLER_PAY_TO]},
        )
        self.assertFalse(bad_pay_to["allow"])
        self.assertEqual(bad_pay_to["code"], "untrusted_pay_to")

        kp = generate_receipt_keypair("py-bind-k1")
        out = {"ok": True}
        issued = issue_receipt(
            private_key=kp["privateKeyPem"],
            issuer={"name": "Seller", "keyId": kp["keyId"], "payTo": SELLER_PAY_TO},
            service={"name": "Seller", "resource": "/v1/q", "method": "POST"},
            request={"method": "POST", "resource": "/v1/q", "body": '{"q":1}'},
            payment={
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": usdc,
                "amountAtomic": "50000",
                "payTo": SELLER_PAY_TO,
                "settlement": {"status": "verify_only", "transactionHash": None},
            },
            output=out,
        )
        # Receipt claims 50000 atomic when challenge only authorized 10000 -> VOID payment_binding_mismatch
        overcharged = evaluate_delivery_arbiter(
            {
                "challenge": {"scheme": "exact", "network": "eip155:8453", "amountAtomic": 10_000, "payTo": SELLER_PAY_TO},
                "request": {"url": "https://api.seller.example/v1/q", "method": "POST", "body": '{"q":1}'},
                "response": {"status": 200, "headers": {"payment-receipt": issued["receiptHeader"]}},
                "body": json.dumps(out),
            },
            expected_issuer_public_keys=[kp["publicKey"]],
        )
        self.assertEqual(overcharged["action"], "VOID")
        self.assertEqual(overcharged["reasonCode"], "payment_binding_mismatch")


if __name__ == "__main__":
    unittest.main()
