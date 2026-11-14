"""Comprehensive unit & security regression tests for paxiom_receipts (Python v0.1.3)."""
from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
PY_ROOT = HERE.parent
V0_ROOT = PY_ROOT.parent
EXAMPLES_DIR = V0_ROOT / "examples"

if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from paxiom_receipts import (  # noqa: E402
    PAXIOM_TRUSTED_PUBLIC_KEYS,
    RECEIPT_HEADER_NAME,
    PaxiomReceiptMiddleware,
    canonicalize,
    decode_receipt_header,
    explain,
    generate_receipt_keypair,
    issue_receipt,
    preflight_x402,
    resolve_safe_api_origin,
    verify_from_files,
    verify_receipt,
    verify_receipt_live,
    verify_response_receipt,
)
from paxiom_receipts.ed25519_pure import _L  # noqa: E402


class PaxiomPythonSdkTests(unittest.TestCase):
    def test_official_node_fixtures_verify_byte_identically(self) -> None:
        valid_res = verify_from_files(
            EXAMPLES_DIR / "valid.receipt.json",
            EXAMPLES_DIR / "valid.output.json",
        )
        self.assertTrue(valid_res["valid"])
        self.assertEqual(valid_res["trustState"], "verified")

        mismatch_res = verify_from_files(
            EXAMPLES_DIR / "valid.receipt.json",
            EXAMPLES_DIR / "output-mismatch.output.json",
        )
        self.assertFalse(mismatch_res["valid"])
        self.assertEqual(mismatch_res["trustState"], "output_hash_mismatch")

        claimed_res = verify_from_files(
            EXAMPLES_DIR / "settlement-claimed-not-checked.receipt.json",
            EXAMPLES_DIR / "valid.output.json",
        )
        self.assertFalse(claimed_res["valid"])
        self.assertEqual(claimed_res["trustState"], "settlement_claimed_not_checked")
        self.assertIn("SETTLEMENT_CLAIMED_NOT_CHECKED", explain(claimed_res))

    def test_keygen_issue_decode_and_security_guards(self) -> None:
        kp = generate_receipt_keypair("py-seller-01")
        out_payload = {"ok": True, "score": 0.0, "items": [1, 2, 3]}
        bundle = issue_receipt(
            private_key=kp["privateKeyPem"],
            issuer={"name": "PySeller", "uri": "https://seller.example", "keyId": kp["keyId"]},
            service={"name": "ScoreAPI", "resource": "https://seller.example/v1/score", "method": "POST"},
            request={"body": {"prompt": "hello"}},
            payment={"settlement": {"status": "verify_only", "transactionHash": None, "checkedByPaxiom": False}},
            output=out_payload,
        )
        decoded = decode_receipt_header(bundle["receiptHeader"])
        verdict = verify_receipt(decoded, output=out_payload)
        self.assertTrue(verdict["valid"])
        self.assertEqual(verdict["trustState"], "verified")

        # FERMI-PAX-03: non-null txHash under verify_only must never resolve to verified
        sneaky = issue_receipt(
            private_key=kp["privateKeyPem"],
            issuer={"name": "PySeller", "keyId": kp["keyId"]},
            service={"name": "ScoreAPI", "resource": "https://seller.example/v1/score", "method": "POST"},
            payment={
                "settlement": {
                    "status": "verify_only",
                    "transactionHash": "0x" + ("ab" * 32),
                    "checkedByPaxiom": False,
                }
            },
            output=out_payload,
        )
        sneaky_verdict = verify_receipt(sneaky["receipt"], output=out_payload)
        self.assertFalse(sneaky_verdict["valid"])
        self.assertEqual(sneaky_verdict["trustState"], "settlement_claimed_not_checked")

        # Untrusted checkedByPaxiom=True is downgraded
        forged_root = issue_receipt(
            private_key=kp["privateKeyPem"],
            issuer={"name": "FakePaxiom", "keyId": kp["keyId"]},
            service={"name": "ScoreAPI", "resource": "https://seller.example/v1/score", "method": "POST"},
            payment={
                "settlement": {
                    "status": "verified_settled",
                    "transactionHash": "0x" + ("cd" * 32),
                    "checkedByPaxiom": True,
                }
            },
            output=out_payload,
        )
        forged_verdict = verify_receipt(
            forged_root["receipt"],
            output=out_payload,
            trusted_paxiom_public_keys=PAXIOM_TRUSTED_PUBLIC_KEYS,
        )
        self.assertEqual(forged_verdict["trustState"], "settlement_claimed_not_checked")

        # Trailing newline must NOT slip past ^...$ patterns in Python re
        tampered_nl = json.loads(json.dumps(bundle["receipt"]))
        tampered_nl["payload"]["delivery"]["outputHash"] = bundle["receipt"]["payload"]["delivery"]["outputHash"] + "\n"
        self.assertEqual(verify_receipt(tampered_nl, output=out_payload)["trustState"], "schema_invalid")
        with self.assertRaises(TypeError):
            preflight_x402("https://seller.example/v1/pay", max_budget_atomic="10000\n")
        with self.assertRaises(TypeError):
            verify_receipt_live(bundle["receipt"], expected_pay_to="0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4\n")

        # FERMI-PAX-05: malleable S >= L Ed25519 signature must be rejected
        raw_sig = bytearray(base64.b64decode(bundle["receipt"]["signature"]["value"]))
        s_int = int.from_bytes(raw_sig[32:64], "little") + _L
        if s_int < (1 << 256):
            raw_sig[32:64] = s_int.to_bytes(32, "little")
            malleable = json.loads(json.dumps(bundle["receipt"]))
            malleable["signature"]["value"] = base64.b64encode(bytes(raw_sig)).decode("ascii")
            self.assertEqual(verify_receipt(malleable, output=out_payload)["trustState"], "invalid_signature")

    def test_canonicalize_utf16_key_sort_and_bounds(self) -> None:
        # U+1F600 (surrogate pair D83D DE00) sorts BEFORE U+E000 in UTF-16 code units!
        obj = {"\ue000": 1, "\U0001f600": 2, "a": -0.0}
        c = canonicalize(obj)
        self.assertEqual(c, '{"a":0,"\U0001f600":2,"\ue000":1}')
        with self.assertRaises(TypeError):
            canonicalize(float("nan"))

    def test_buyer_client_helpers_and_safety_bounds(self) -> None:
        self.assertEqual(resolve_safe_api_origin("https://api.paxiom.org/v1"), "https://api.paxiom.org")
        self.assertEqual(resolve_safe_api_origin("http://127.0.0.1:8787"), "http://127.0.0.1:8787")
        with self.assertRaises(TypeError):
            resolve_safe_api_origin("http://api.paxiom.org")
        with self.assertRaises(TypeError):
            resolve_safe_api_origin("https://user:secret@api.paxiom.org")

        # Absent and malformed header never raise
        self.assertFalse(verify_response_receipt({})["present"])
        mal = verify_response_receipt({RECEIPT_HEADER_NAME: "not-valid-json!!!"})
        self.assertEqual(mal["trustState"], "malformed_header")

        kp = generate_receipt_keypair("paxiom-mock")
        mock_report = {"ok": True, "verdict": "proceed", "riskLevel": "low"}
        signed = issue_receipt(
            private_key=kp["privateKeyPem"],
            issuer={"name": "Paxiom Receipt Verifier", "keyId": kp["keyId"]},
            service={"name": "Preflight", "resource": "https://api.paxiom.org/v1/x402/preflight", "method": "POST"},
            output=mock_report,
        )

        def fake_transport(url, headers, body, timeout, max_bytes):  # noqa: ANN001
            if "preflight" in url:
                return 200, {RECEIPT_HEADER_NAME: signed["receiptHeader"]}, json.dumps(mock_report)
            counter = issue_receipt(
                private_key=kp["privateKeyPem"],
                issuer={"name": "Paxiom Receipt Verifier", "keyId": kp["keyId"]},
                service={"name": "Live", "resource": url, "method": "POST"},
                payment={
                    "settlement": {
                        "status": "verified_settled",
                        "transactionHash": "0x" + ("11" * 32),
                        "checkedByPaxiom": True,
                    }
                },
                output={"hello": "world"},
            )["receipt"]
            return 200, {}, json.dumps({"valid": True, "trustState": "verified", "counterAttestedReceipt": counter})

        pre = preflight_x402(
            "https://seller.example/v1/pay",
            max_budget_atomic="10000",
            trusted_paxiom_public_keys=[kp["publicKey"]],
            transport=fake_transport,
        )
        self.assertTrue(pre["ok"])
        self.assertEqual(pre["verdict"], "proceed")
        self.assertTrue(pre["receiptVerification"]["valid"])

        live = verify_receipt_live(
            signed["receipt"],
            output={"hello": "world"},
            expected_pay_to="0x9786F5532ab7d7556CDa53E3f6c2d937c9b87Bc4",
            trusted_paxiom_public_keys=[kp["publicKey"]],
            transport=fake_transport,
        )
        self.assertTrue(live["ok"])
        self.assertTrue(live["counterAttestedVerification"]["valid"])

        # Redirect must raise
        with self.assertRaises(RuntimeError):
            preflight_x402(
                "https://seller.example/v1/pay",
                transport=lambda u, h, b, t, m: (302, {"location": "https://evil.example"}, ""),
            )

    def test_asgi_middleware_signs_2xx_json_and_skips_errors(self) -> None:
        kp = generate_receipt_keypair("asgi-seller-01")
        captured_receipts: list[dict] = []

        async def demo_app(scope, receive, send):  # noqa: ANN001
            await receive()
            if scope["path"] == "/fail":
                await send({"type": "http.response.start", "status": 500, "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body", "body": b'{"error":"boom"}', "more_body": False})
                return
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": b'{"result":42}', "more_body": False})

        mw = PaxiomReceiptMiddleware(
            demo_app,
            private_key=kp["privateKeyPem"],
            issuer={"name": "FastAPISeller", "keyId": kp["keyId"]},
            on_receipt=captured_receipts.append,
        )

        async def call_asgi(path: str) -> tuple[int, dict[str, str], bytes]:
            sent: list[dict] = []

            async def recv():
                return {"type": "http.request", "body": b'{"q":1}', "more_body": False}

            async def snd(msg):
                sent.append(msg)

            await mw(
                {"type": "http", "method": "POST", "scheme": "https", "path": path, "headers": [(b"host", b"api.seller.example")]},
                recv,
                snd,
            )
            hdrs = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in sent[0]["headers"]}
            return sent[0]["status"], hdrs, sent[1]["body"]

        status_ok, hdrs_ok, body_ok = asyncio.run(call_asgi("/v1/infer"))
        self.assertEqual(status_ok, 200)
        self.assertIn(RECEIPT_HEADER_NAME, hdrs_ok)
        ver = verify_response_receipt(hdrs_ok, output=json.loads(body_ok.decode("utf-8")))
        self.assertTrue(ver["valid"])
        self.assertEqual(len(captured_receipts), 1)

        status_err, hdrs_err, _ = asyncio.run(call_asgi("/fail"))
        self.assertEqual(status_err, 500)
        self.assertNotIn(RECEIPT_HEADER_NAME, hdrs_err)


    def test_bidirectional_nodejs_python_interop(self) -> None:
        import shutil as _shutil
        import subprocess as _sp

        node_bin = _shutil.which("node")
        if not node_bin:
            return
        # Python generates PKCS#8 PEM + signs receipt -> Node verifies it & signs a reply receipt -> Python verifies Node's receipt
        py_kp = generate_receipt_keypair("cross-lang-key-01")
        payload_out = {"bridge": "node-python", "unicode": "αβγ😀", "zero": 0}
        py_issued = issue_receipt(
            private_key=py_kp["privateKeyPem"],
            issuer={"name": "PyIssuer", "keyId": py_kp["keyId"]},
            service={"name": "Interop", "resource": "https://api.example/v1", "method": "POST"},
            output=payload_out,
        )
        node_script = """
import { verifyReceipt, issueReceipt } from './src/index.mjs';
const input = JSON.parse(process.env.CROSS_INPUT);
const v = verifyReceipt(input.pyReceipt, { output: input.output });
if (!v.valid || v.trustState !== 'verified') {
  throw new Error('Node failed to verify Python receipt: ' + JSON.stringify(v));
}
const nodeIssued = issueReceipt({
  privateKey: input.pem,
  issuer: { name: 'NodeIssuer', keyId: input.keyId },
  service: { name: 'Interop', resource: 'https://api.example/v1', method: 'POST' },
  output: input.output
});
process.stdout.write(JSON.stringify({ nodeHeader: nodeIssued.receiptHeader, receiptHash: v.receiptHash }));
"""
        proc = _sp.run(
            [node_bin, "--input-type=module", "-e", node_script],
            cwd=str(V0_ROOT),
            env={
                **__import__("os").environ,
                "CROSS_INPUT": json.dumps(
                    {
                        "pem": py_kp["privateKeyPem"],
                        "keyId": py_kp["keyId"],
                        "pyReceipt": py_issued["receipt"],
                        "output": payload_out,
                    }
                ),
            },
            capture_output=True,
            text=True,
            check=True,
        )
        node_out = json.loads(proc.stdout)
        py_check_of_node = verify_response_receipt(
            {RECEIPT_HEADER_NAME: node_out["nodeHeader"]},
            output=payload_out,
        )
        self.assertTrue(py_check_of_node["valid"])
        self.assertEqual(py_check_of_node["trustState"], "verified")

if __name__ == "__main__":
    unittest.main()
