"""Regression checks for the driver, real Cedar evaluation, and chain scope."""
import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature

import gdi_driver as gdi

REPO = Path(__file__).resolve().parents[2]


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(REPO / "fixtures", self.root / "fixtures")
        self.out = self.root / "receipts" / "gdi"
        self.policy = self.root / "fixtures/policy/autoresearch-safe.cedar"
        self.emit()

    def emit(self):
        with contextlib.redirect_stdout(io.StringIO()):
            gdi.emit(self.root)

    def receipts(self):
        return [json.loads(f.read_text()) for f in sorted(self.out.glob("*.json"))]

    def check_chain(self):
        return subprocess.run(
            [sys.executable, str(REPO / "conformance/check_chain.py"),
             str(self.out), str(REPO)], capture_output=True, text=True)

    def write_receipts(self, receipts):
        for path, receipt in zip(sorted(self.out.glob("*.json")), receipts):
            path.write_text(json.dumps(receipt))

    def test_valid_chain_and_current_outcomes(self):
        result = self.check_chain()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([r["payload"]["decision"] for r in self.receipts()],
                         ["allow", "allow", "deny", "allow"])

    def test_links_bind_signed_envelope_and_genesis_omits_all_aliases(self):
        receipts = self.receipts()
        for name in ("parent_receipt_hash", "previous_receipt_hash", "prev_hash",
                     "previousReceiptHash"):
            self.assertNotIn(name, receipts[0])
            self.assertNotIn(name, receipts[0]["payload"])
        for previous, current in zip(receipts, receipts[1:]):
            self.assertEqual(current["payload"]["previousReceiptHash"],
                             gdi.sha256p(gdi.jcs(previous)))
            unsigned = {k: v for k, v in previous.items() if k != "signature"}
            self.assertNotEqual(current["payload"]["previousReceiptHash"],
                                gdi.sha256p(gdi.jcs(unsigned)))

    def test_each_signature_and_gdr_digest_verify(self):
        for receipt in self.receipts():
            unsigned = {k: v for k, v in receipt.items() if k != "signature"}
            gdi._PRIV.public_key().verify(bytes.fromhex(receipt["signature"]), gdi.jcs(unsigned))
            self.assertEqual(receipt["payload"]["result_hash"],
                             gdi.sha256p(gdi.jcs(receipt["payload"]["gdr"])))
            unsigned["payload"]["gdr"]["confidence_score"] = 0.99
            with self.assertRaises(InvalidSignature):
                gdi._PRIV.public_key().verify(bytes.fromhex(receipt["signature"]), gdi.jcs(unsigned))

    def test_invalid_chain_conventions_are_rejected(self):
        original = self.receipts()
        mutations = {
            "null genesis": lambda rs: rs[0]["payload"].update(previousReceiptHash=None),
            "legacy field": lambda rs: rs[1]["payload"].update(
                parent_receipt_hash=rs[1]["payload"].pop("previousReceiptHash")),
            "unsigned predecessor": lambda rs: rs[1]["payload"].update(previousReceiptHash=gdi.sha256p(
                gdi.jcs({k: v for k, v in rs[0].items() if k != "signature"}))),
            "changed predecessor signature": lambda rs: rs[0].update(signature="00" * 64),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                receipts = copy.deepcopy(original)
                mutate(receipts)
                self.write_receipts(receipts)
                self.assertEqual(self.check_chain().returncode, 1)

    def test_policy_digest_matches_independent_fixture_helper(self):
        expected = subprocess.check_output(
            [sys.executable, str(REPO / "harness/policy-digest.py"), str(self.policy)], text=True).strip()
        self.assertEqual({r["payload"]["policy_digest"] for r in self.receipts()}, {expected})

    def test_policy_change_changes_decisions_and_digest(self):
        before = self.receipts()[0]["payload"]["policy_digest"]
        self.policy.write_text("permit(principal, action, resource);\n")
        self.emit()
        self.assertEqual([r["payload"]["decision"] for r in self.receipts()], ["allow"] * 4)
        self.assertNotEqual(self.receipts()[0]["payload"]["policy_digest"], before)

    def test_expected_decision_is_not_an_input_to_evaluation(self):
        for path in (self.root / "fixtures/inputs").glob("*.json"):
            fixture = json.loads(path.read_text())
            fixture["expected_decision"] = "wrong"
            path.write_text(json.dumps(fixture))
        self.emit()
        self.assertEqual([r["payload"]["decision"] for r in self.receipts()],
                         ["allow", "allow", "deny", "allow"])

    def test_evaluation_error_preserves_previous_output(self):
        before = {p.name: p.read_bytes() for p in self.out.glob("*.json")}
        # Real Cedar rejects string membership with `in`. The old hardcoded
        # decision function would silently ignore this malformed policy.
        self.policy.write_text('permit(principal, action, resource) when { "git" in ["git"] };')
        with self.assertRaises(ValueError):
            self.emit()
        self.assertEqual({p.name: p.read_bytes() for p in self.out.glob("*.json")}, before)

    def test_malformed_later_fixture_does_not_write_partial_chain(self):
        before = {p.name: p.read_bytes() for p in self.out.glob("*.json")}
        sorted((self.root / "fixtures/inputs").glob("*.json"))[-1].write_text("{")
        with self.assertRaises(ValueError):
            self.emit()
        self.assertEqual({p.name: p.read_bytes() for p in self.out.glob("*.json")}, before)

    def test_stale_receipts_removed_only_after_success(self):
        stale = self.out / "stale.json"
        stale.write_text("{}")
        self.emit()
        self.assertFalse(stale.exists())
        self.assertEqual(len(self.receipts()), 4)

    def test_jcs_numbers_and_utf16_key_order(self):
        self.assertEqual(gdi.jcs({"n": [1.0, -0.0, 1e-7]}), b'{"n":[1,0,1e-7]}')
        # UTF-16 sorts a surrogate pair before U+E000; Python codepoint sort does not.
        self.assertEqual(gdi.jcs({"\ue000": 1, "\U00010000": 2}),
                         '{"\U00010000":2,"\ue000":1}'.encode())

    def test_nested_input_and_test_key_are_bound(self):
        self.assertEqual((REPO / "implementations/gdi/key.hex").read_text().strip(), gdi.PUBKEY_HEX)
        path = sorted((self.root / "fixtures/inputs").glob("*.json"))[0]
        fixture = json.loads(path.read_text())
        fixture["tool_input"]["nested"] = {"amount": 10}
        path.write_text(json.dumps(fixture))
        self.emit()
        before = self.receipts()[0]
        fixture["tool_input"]["nested"]["amount"] = 11
        path.write_text(json.dumps(fixture))
        self.emit()
        after = self.receipts()[0]
        self.assertNotEqual(before["payload"]["params_hash"], after["payload"]["params_hash"])
        self.assertNotEqual(before["signature"], after["signature"])


if __name__ == "__main__":
    unittest.main()
