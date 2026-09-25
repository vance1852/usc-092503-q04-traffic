from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timezone

from evidence_custody.clock import FrozenClock
from evidence_custody.errors import Conflict, Forbidden, InvalidState, ValidationFailed
from evidence_custody.service import EvidenceCustodyService, mask_contact


DIGEST_V1 = "1" * 64
DIGEST_V2 = "2" * 64
DIGEST_V3 = "3" * 64
DIGEST_TAMPERED = "9" * 64


class CustodyServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc))
        self.service = EvidenceCustodyService(self.connection, self.clock)
        for user_id, role, contact in (
            ("collector", "collector", "13800001111"),
            ("custodian", "custodian", "13800002222"),
            ("officer", "case_officer", "13800003333"),
            ("reviewer", "reviewer", "13800004444"),
            ("auditor", "auditor", "13800005555"),
        ):
            self.service.create_user(user_id, user_id, role, contact)
        self.service.register_location("custodian", "vault", "证据库房", "warehouse")
        self.service.register_location("custodian", "review-room", "调阅室", "cabinet")
        self.service.register_package("collector", "pkg-1", "case-1", "现场证据包", "vault", DIGEST_V1, "原始封存")

    def tearDown(self) -> None:
        self.connection.close()

    def _handover_to_custodian(self) -> None:
        handover = self.service.initiate_handover("collector", "pkg-1", "custodian", "vault", "入库")
        self.service.confirm_handover(
            "custodian", handover["handover_id"], True, received_digest=handover["content_sha256"]
        )

    def test_full_flow_chain_intact(self) -> None:
        self.service.upload_version("collector", "pkg-1", DIGEST_V2, "补充材料")
        handover = self.service.initiate_handover("collector", "pkg-1", "custodian", "vault", "入库")
        self.service.confirm_handover("custodian", handover["handover_id"], True, received_digest=DIGEST_V2)
        self.service.retrieve_package("officer", "pkg-1", "调证字〔2026〕1 号", "责任认定")
        returned = self.service.initiate_handover("officer", "pkg-1", "custodian", "vault", "归还")
        self.service.confirm_handover("custodian", returned["handover_id"], True, received_digest=DIGEST_V2)
        self.service.record_determination("officer", "pkg-1", 2, "甲方主要责任")
        chain = self.service.get_chain("officer", "pkg-1")
        self.assertEqual(
            [event["event_type"] for event in chain["events"]],
            ["register", "version_upload", "handover", "retrieve", "handover", "determination"],
        )
        self.assertEqual(chain["package"]["custody_status"], "sealed")
        self.assertEqual(chain["package"]["current_holder"]["user_id"], "custodian")
        version2 = [row for row in chain["versions"] if row["version_no"] == 2][0]
        self.assertTrue(version2["locked_by_determination"])
        self.assertEqual(chain["verification"]["status"], "intact")
        self.assertEqual(chain["verification"]["event_count"], 6)

    def test_handover_parties_must_be_in_limited_roles(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.initiate_handover("collector", "pkg-1", "auditor", "vault")
        with self.assertRaises(Forbidden):
            self.service.initiate_handover("auditor", "pkg-1", "custodian", "vault")
        handover = self.service.initiate_handover("collector", "pkg-1", "custodian", "vault")
        self.connection.execute("UPDATE users SET role='auditor' WHERE user_id='custodian'")
        with self.assertRaises(Forbidden):
            self.service.confirm_handover("custodian", handover["handover_id"], True, received_digest=DIGEST_V1)

    def test_only_designated_receiver_confirms(self) -> None:
        handover = self.service.initiate_handover("collector", "pkg-1", "custodian", "vault")
        with self.assertRaises(Forbidden):
            self.service.confirm_handover("collector", handover["handover_id"], True, received_digest=DIGEST_V1)
        with self.assertRaises(Forbidden):
            self.service.confirm_handover("reviewer", handover["handover_id"], True, received_digest=DIGEST_V1)
        with self.assertRaises(ValidationFailed):
            self.service.initiate_handover("collector", "pkg-1", "collector", "vault")

    def test_digest_mismatch_must_be_rejected(self) -> None:
        handover = self.service.initiate_handover("collector", "pkg-1", "custodian", "vault")
        with self.assertRaises(ValidationFailed):
            self.service.confirm_handover("custodian", handover["handover_id"], True, received_digest=DIGEST_V2)
        result = self.service.confirm_handover(
            "custodian", handover["handover_id"], False, reason="封装破损，摘要对不上"
        )
        self.assertEqual(result["status"], "rejected")
        chain = self.service.get_chain("custodian", "pkg-1")
        self.assertEqual(chain["events"][-1]["event_type"], "reject")
        self.assertEqual(chain["package"]["current_holder"]["user_id"], "collector")
        self.assertEqual(chain["handovers"][0]["reject_reason"], "封装破损，摘要对不上")
        self.assertEqual(chain["verification"]["status"], "intact")

    def test_reject_requires_reason(self) -> None:
        handover = self.service.initiate_handover("collector", "pkg-1", "custodian", "vault")
        with self.assertRaises(ValidationFailed):
            self.service.confirm_handover("custodian", handover["handover_id"], False, reason=" ")

    def test_pending_handover_blocks_other_operations(self) -> None:
        self.service.initiate_handover("collector", "pkg-1", "custodian", "vault")
        with self.assertRaises(Conflict):
            self.service.initiate_handover("collector", "pkg-1", "custodian", "vault")
        with self.assertRaises(InvalidState):
            self.service.upload_version("collector", "pkg-1", DIGEST_V2)
        with self.assertRaises(InvalidState):
            self.service.report_loss("collector", "pkg-1", "移交途中遗失")
        with self.assertRaises(InvalidState):
            self.service.retrieve_package("officer", "pkg-1", "调证字 1 号", "审查")
        with self.assertRaises(InvalidState):
            self.service.reseal_package("custodian", "pkg-1", DIGEST_V2, "vault")

    def test_loss_and_reseal_recovers_continuous_state(self) -> None:
        self.service.report_loss("collector", "pkg-1", "移交途中遗失")
        with self.assertRaises(InvalidState):
            self.service.initiate_handover("collector", "pkg-1", "custodian", "vault")
        with self.assertRaises(InvalidState):
            self.service.upload_version("collector", "pkg-1", DIGEST_V2)
        with self.assertRaises(InvalidState):
            self.service.retrieve_package("officer", "pkg-1", "调证字 1 号", "审查")
        with self.assertRaises(InvalidState):
            self.service.report_loss("collector", "pkg-1", "重复报告")
        resealed = self.service.reseal_package("custodian", "pkg-1", DIGEST_V2, "vault", "找回后重新封装")
        self.assertEqual(resealed["version_no"], 2)
        chain = self.service.get_chain("custodian", "pkg-1")
        self.assertEqual(chain["package"]["custody_status"], "sealed")
        self.assertEqual(chain["package"]["current_holder"]["user_id"], "custodian")
        self.assertEqual(
            [event["event_type"] for event in chain["events"]], ["register", "loss", "reseal"]
        )
        self.assertEqual(chain["verification"]["status"], "intact")

    def test_retrieve_requires_legal_doc_and_moves_custody(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.retrieve_package("officer", "pkg-1", "", "审查")
        with self.assertRaises(Forbidden):
            self.service.retrieve_package("custodian", "pkg-1", "调证字 1 号", "审查")
        self.service.retrieve_package("reviewer", "pkg-1", "调证字〔2026〕2 号", "复核")
        chain = self.service.get_chain("reviewer", "pkg-1")
        self.assertEqual(chain["package"]["custody_status"], "out_on_retrieval")
        self.assertIsNone(chain["package"]["current_location"])
        self.assertEqual(chain["package"]["current_holder"]["user_id"], "reviewer")
        self.assertEqual(chain["events"][-1]["detail"]["legal_doc_no"], "调证字〔2026〕2 号")
        with self.assertRaises(InvalidState):
            self.service.retrieve_package("officer", "pkg-1", "调证字 3 号", "再次调阅")
        with self.assertRaises(InvalidState):
            self.service.reseal_package("custodian", "pkg-1", DIGEST_V2, "vault")

    def test_determination_locks_version_and_uploads_only_append(self) -> None:
        self.service.record_determination("officer", "pkg-1", 1, "认定结论")
        with self.assertRaises(Conflict):
            self.service.record_determination("officer", "pkg-1", 1, "重复认定")
        uploaded = self.service.upload_version("collector", "pkg-1", DIGEST_V2, "申诉补充材料")
        self.assertEqual(uploaded["version_no"], 2)
        chain = self.service.get_chain("officer", "pkg-1")
        version1 = [row for row in chain["versions"] if row["version_no"] == 1][0]
        self.assertTrue(version1["locked_by_determination"])
        self.assertEqual(chain["determinations"][0]["content_sha256"], DIGEST_V1)
        self.assertEqual(chain["verification"]["status"], "intact")

    def test_contact_masking_follows_role_permission(self) -> None:
        self._handover_to_custodian()
        officer_view = self.service.get_chain("officer", "pkg-1")
        auditor_view = self.service.get_chain("auditor", "pkg-1")
        reviewer_view = self.service.get_chain("reviewer", "pkg-1")
        self.assertFalse(officer_view["contacts_masked"])
        self.assertEqual(officer_view["package"]["current_holder"]["contact"], "13800002222")
        self.assertTrue(auditor_view["contacts_masked"])
        self.assertEqual(auditor_view["package"]["current_holder"]["contact"], "138****2222")
        self.assertNotIn("13800002222", str(auditor_view))
        self.assertNotIn("13800001111", str(reviewer_view))
        with self.assertRaises(Forbidden):
            self.service.get_chain("collector", "pkg-1")

    def test_mask_contact_shapes(self) -> None:
        self.assertEqual(mask_contact("13800001111"), "138****1111")
        self.assertEqual(mask_contact("zhang@example.com"), "z***")
        self.assertEqual(mask_contact("x"), "*")

    def test_verify_detects_deleted_middle_event(self) -> None:
        self.service.upload_version("collector", "pkg-1", DIGEST_V2, "补充")
        self._handover_to_custodian()
        self.connection.execute("DELETE FROM custody_events WHERE package_id='pkg-1' AND seq=2")
        verification = self.service.verify_chain("auditor", "pkg-1")
        self.assertEqual(verification["status"], "broken")
        kinds = [item["kind"] for item in verification["breaks"]]
        self.assertIn("sequence_gap", kinds)
        self.assertIn("prev_hash_mismatch", kinds)
        gap = [item for item in verification["breaks"] if item["kind"] == "sequence_gap"][0]
        self.assertEqual(gap["seq"], 3)

    def test_verify_detects_tampered_event_content(self) -> None:
        self.service.upload_version("collector", "pkg-1", DIGEST_V2, "补充")
        self.connection.execute(
            "UPDATE custody_events SET detail_json='{\"note\":\"篡改\"}' WHERE package_id='pkg-1' AND seq=2"
        )
        verification = self.service.verify_chain("auditor", "pkg-1")
        self.assertEqual(verification["status"], "broken")
        mismatches = [item for item in verification["breaks"] if item["kind"] == "event_hash_mismatch"]
        self.assertEqual([item["seq"] for item in mismatches], [2])

    def test_verify_detects_overwritten_determination_version(self) -> None:
        self.service.record_determination("officer", "pkg-1", 1, "认定结论")
        self.connection.execute(
            "UPDATE evidence_versions SET content_sha256=? WHERE package_id='pkg-1' AND version_no=1",
            (DIGEST_TAMPERED,),
        )
        verification = self.service.verify_chain("officer", "pkg-1")
        self.assertEqual(verification["status"], "broken")
        kinds = [item["kind"] for item in verification["breaks"]]
        self.assertIn("digest_mismatch", kinds)
        self.assertIn("determination_digest_mismatch", kinds)
        digest_break = [item for item in verification["breaks"] if item["kind"] == "digest_mismatch"][0]
        self.assertEqual(digest_break["seq"], 1)

    def test_verify_detects_ledger_tampering(self) -> None:
        self.connection.execute(
            "UPDATE evidence_packages SET current_holder_id='officer' WHERE package_id='pkg-1'"
        )
        verification = self.service.verify_chain("auditor", "pkg-1")
        self.assertEqual(verification["status"], "broken")
        kinds = [item["kind"] for item in verification["breaks"]]
        self.assertIn("state_divergence", kinds)

    def test_verify_detects_deleted_determination_event(self) -> None:
        self.service.record_determination("officer", "pkg-1", 1, "认定结论")
        self.connection.execute("DELETE FROM custody_events WHERE package_id='pkg-1' AND event_type='determination'")
        verification = self.service.verify_chain("auditor", "pkg-1")
        kinds = [item["kind"] for item in verification["breaks"]]
        self.assertIn("determination_event_missing", kinds)

    def test_inactive_user_is_forbidden(self) -> None:
        self.connection.execute("UPDATE users SET active=0 WHERE user_id='collector'")
        with self.assertRaises(Forbidden):
            self.service.upload_version("collector", "pkg-1", DIGEST_V2)

    def test_digest_format_is_validated(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.register_package("collector", "pkg-2", "case-2", "包", "vault", "not-a-digest")
        with self.assertRaises(ValidationFailed):
            self.service.upload_version("collector", "pkg-1", "z" * 64)


if __name__ == "__main__":
    unittest.main()
