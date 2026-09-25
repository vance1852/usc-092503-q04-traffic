from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone

from evidence_review.clock import FrozenClock
from evidence_review.custody import CustodyService, mask_contact, verify_chain
from evidence_review.errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed


CONTENT_A = "a" * 64
PACKAGE_A = "b" * 64
PACKAGE_B = "c" * 64
PACKAGE_C = "d" * 64
PACKAGE_D = "e" * 64


class CustodyTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.clock = FrozenClock(datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc))
        self.service = CustodyService(self.connection, self.clock)
        for user_id, role in (
            ("op1", "operator"),
            ("op2", "operator"),
            ("stat", "statistician"),
            ("approver", "approver"),
            ("auditor", "auditor"),
        ):
            self.connection.execute(
                "INSERT INTO users(user_id,display_name,role,active) VALUES(?,?,?,1)",
                (user_id, user_id, role),
            )
        self.service.register_location("op1", "vault-1", "一号物证库", "vault")
        self.service.register_location("op1", "room-1", "阅卷室", "room")

    def tearDown(self) -> None:
        self.connection.close()

    def register(self, material_id: str = "m1", content: str = CONTENT_A, package: str = PACKAGE_A) -> dict:
        return self.service.register_material(
            "op1", material_id, "现场视频", "video", "vault-1",
            content, package, 1024, "video/mp4", "首版封存",
        )

    def transfer_to_op2(self, material_id: str = "m1", accept: bool = True, note: str = "完好") -> dict:
        proposed = self.service.propose_transfer("op1", material_id, "op2", "vault-1", "复核移交")
        return self.service.respond_transfer("op2", proposed["transfer_id"], accept, note)


class RegistrationTests(CustodyTestBase):
    def test_register_creates_first_version_and_sealed_event(self) -> None:
        result = self.register()
        self.assertEqual(result["version_no"], 1)
        material = self.connection.execute(
            "SELECT * FROM custody_materials WHERE material_id='m1'"
        ).fetchone()
        self.assertEqual(material["state"], "sealed")
        self.assertEqual(material["chain_length"], 1)
        self.assertIsNotNone(material["last_event_hash"])
        view = self.service.chain_view("auditor", "m1")
        self.assertTrue(view["verification"]["intact"])
        self.assertEqual(view["versions"][0]["content_sha256"], CONTENT_A)

    def test_hashes_must_be_sha256(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.register_material(
                "op1", "m1", "视频", "video", "vault-1", "ABC", PACKAGE_A, 1, "video/mp4",
            )

    def test_package_hash_must_differ_from_content(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.register(content=CONTENT_A, package=CONTENT_A)

    def test_unknown_location_and_role_rejected(self) -> None:
        with self.assertRaises(NotFound):
            self.service.register_material(
                "op1", "m1", "视频", "video", "nope", CONTENT_A, PACKAGE_A, 1, "video/mp4",
            )
        with self.assertRaises(Forbidden):
            self.service.register_material(
                "stat", "m1", "视频", "video", "vault-1", CONTENT_A, PACKAGE_A, 1, "video/mp4",
            )

    def test_duplicate_material_id_conflicts(self) -> None:
        self.register()
        with self.assertRaises(Conflict):
            self.register()


class TransferTests(CustodyTestBase):
    def test_two_party_confirmation_updates_holder_and_state(self) -> None:
        self.register()
        result = self.transfer_to_op2()
        self.assertEqual(result["state"], "accepted")
        material = self.connection.execute(
            "SELECT * FROM custody_materials WHERE material_id='m1'"
        ).fetchone()
        self.assertEqual(material["state"], "stored")
        self.assertEqual(material["holder_user_id"], "op2")
        transfer = self.connection.execute(
            "SELECT * FROM custody_transfers WHERE material_id='m1'"
        ).fetchone()
        self.assertEqual(transfer["state"], "accepted")
        self.assertIsNotNone(transfer["responded_at"])

    def test_rejection_returns_material_to_sender_with_continuous_state(self) -> None:
        self.register()
        proposed = self.service.propose_transfer("op1", "m1", "op2", "vault-1", "移交")
        rejected = self.service.respond_transfer("op2", proposed["transfer_id"], False, "封装破损，拒收")
        self.assertEqual(rejected["state"], "rejected")
        material = self.connection.execute(
            "SELECT * FROM custody_materials WHERE material_id='m1'"
        ).fetchone()
        self.assertEqual(material["state"], "rejected")
        self.assertEqual(material["holder_user_id"], "op1")
        view = self.service.chain_view("auditor", "m1")
        self.assertTrue(view["verification"]["intact"])
        self.assertEqual(
            [event["event_type"] for event in view["events"]],
            ["material.registered", "transfer.proposed", "transfer.rejected"],
        )

    def test_reject_requires_reason(self) -> None:
        self.register()
        proposed = self.service.propose_transfer("op1", "m1", "op2", "vault-1", "移交")
        with self.assertRaises(ValidationFailed):
            self.service.respond_transfer("op2", proposed["transfer_id"], False, "  ")

    def test_only_holder_may_propose_and_only_receiver_respond(self) -> None:
        self.register()
        # 非持有人在稳定状态发起交接：禁止。
        with self.assertRaises(Forbidden):
            self.service.propose_transfer("op2", "m1", "op1", "vault-1", "非持有人发起")
        proposed = self.service.propose_transfer("op1", "m1", "op2", "vault-1", "移交")
        with self.assertRaises(Forbidden):
            self.service.respond_transfer("op1", proposed["transfer_id"], True, "我不是接收方")
        # statistician 不具备接收角色（校验在事务前，任何状态下都拒绝）。
        with self.assertRaises(Forbidden):
            self.service.propose_transfer("op1", "m1", "stat", "vault-1", "交给统计员")

    def test_self_transfer_rejected(self) -> None:
        self.register()
        with self.assertRaises(ValidationFailed):
            self.service.propose_transfer("op1", "m1", "op1", "vault-1", "自交自接")

    def test_double_respond_rejected(self) -> None:
        self.register()
        proposed = self.service.propose_transfer("op1", "m1", "op2", "vault-1", "移交")
        self.service.respond_transfer("op2", proposed["transfer_id"], True, "ok")
        with self.assertRaises(InvalidState):
            self.service.respond_transfer("op2", proposed["transfer_id"], True, "重复确认")

    def test_cancel_transfer_restores_prior_state(self) -> None:
        self.register()
        proposed = self.service.propose_transfer("op1", "m1", "op2", "vault-1", "移交")
        cancelled = self.service.cancel_transfer("op1", proposed["transfer_id"], "接收人离岗")
        self.assertEqual(cancelled["state"], "cancelled")
        material = self.connection.execute(
            "SELECT state FROM custody_materials WHERE material_id='m1'"
        ).fetchone()
        self.assertEqual(material["state"], "sealed")
        self.assertTrue(self.service.chain_view("auditor", "m1")["verification"]["intact"])

    def test_other_party_cannot_cancel(self) -> None:
        self.register()
        proposed = self.service.propose_transfer("op1", "m1", "op2", "vault-1", "移交")
        with self.assertRaises(Forbidden):
            self.service.cancel_transfer("op2", proposed["transfer_id"], "不是我发起的")


class LossAndResealTests(CustodyTestBase):
    def test_loss_then_found_round_trip(self) -> None:
        self.register()
        lost = self.service.report_loss("op1", "m1", "搬运中下落不明")
        self.assertEqual(lost["state"], "lost")
        self.assertIsNone(
            self.connection.execute(
                "SELECT holder_user_id FROM custody_materials WHERE material_id='m1'"
            ).fetchone()["holder_user_id"]
        )
        found = self.service.report_found("op1", "m1", "vault-1", "在角落找到，封装完好")
        self.assertEqual(found["state"], "stored")
        self.assertTrue(self.service.chain_view("auditor", "m1")["verification"]["intact"])

    def test_loss_requires_explanation_and_stable_state(self) -> None:
        self.register()
        with self.assertRaises(ValidationFailed):
            self.service.report_loss("op1", "m1", " ")
        self.service.propose_transfer("op1", "m1", "op2", "vault-1", "移交")
        with self.assertRaises(InvalidState):
            self.service.report_loss("op1", "m1", "交接中不能报损")

    def test_reseal_keeps_content_hash_changes_package_hash(self) -> None:
        self.register()
        result = self.service.reseal("op1", "m1", PACKAGE_B, "approver", "外封装老化重新封装")
        self.assertEqual(result["version_no"], 2)
        versions = self.connection.execute(
            "SELECT version_no,content_sha256,package_sha256 FROM custody_material_versions "
            "WHERE material_id='m1' ORDER BY version_no"
        ).fetchall()
        self.assertEqual(versions[0]["content_sha256"], versions[1]["content_sha256"])
        self.assertNotEqual(versions[0]["package_sha256"], versions[1]["package_sha256"])
        view = self.service.chain_view("auditor", "m1")
        self.assertEqual(view["material"]["state"], "resealed")
        self.assertTrue(view["verification"]["intact"])

    def test_reseal_requires_qualified_witness(self) -> None:
        self.register()
        with self.assertRaises(Forbidden):
            self.service.reseal("op1", "m1", PACKAGE_B, "op2", "见证人角色不符")
        with self.assertRaises(ValidationFailed):
            self.service.reseal("op1", "m1", PACKAGE_B, "approver", " ")

    def test_reseal_rejects_duplicate_package(self) -> None:
        self.register()
        with self.assertRaises(Conflict):
            self.service.reseal("op1", "m1", PACKAGE_A, "approver", "封装没变")


class VersionTests(CustodyTestBase):
    def test_upload_is_append_only_and_never_overwrites(self) -> None:
        self.register()
        uploaded = self.service.upload_version("op1", "m1", "f" * 64, PACKAGE_B, 2048, "补采完整版")
        self.assertEqual(uploaded["version_no"], 2)
        versions = self.connection.execute(
            "SELECT version_no,content_sha256 FROM custody_material_versions "
            "WHERE material_id='m1' ORDER BY version_no"
        ).fetchall()
        self.assertEqual(len(versions), 2)
        self.assertEqual(versions[0]["content_sha256"], CONTENT_A)
        self.assertTrue(self.service.chain_view("auditor", "m1")["verification"]["intact"])

    def test_upload_requires_change_note_and_unique_package(self) -> None:
        self.register()
        with self.assertRaises(ValidationFailed):
            self.service.upload_version("op1", "m1", "f" * 64, PACKAGE_B, 1, " ")
        with self.assertRaises(Conflict):
            self.service.upload_version("op1", "m1", "f" * 64, PACKAGE_A, 1, "封装重复")

    def test_locked_version_cannot_be_covered_by_later_upload(self) -> None:
        self.register()
        self.service.lock_for_decision("approver", "m1", "认-2026-001")
        with self.assertRaises(InvalidState):
            self.service.upload_version("op1", "m1", "f" * 64, PACKAGE_B, 1, "试图覆盖")
        with self.assertRaises(InvalidState):
            self.service.reseal("op1", "m1", PACKAGE_B, "approver", "锁定后重新封装")
        with self.assertRaises(InvalidState):
            self.service.lock_for_decision("approver", "m1", "认-2026-002")
        versions = self.connection.execute(
            "SELECT count(*) FROM custody_material_versions WHERE material_id='m1'"
        ).fetchone()[0]
        self.assertEqual(versions, 1)

    def test_lock_requires_decision_reference_and_role(self) -> None:
        self.register()
        with self.assertRaises(Forbidden):
            self.service.lock_for_decision("op1", "m1", "认-1")
        with self.assertRaises(ValidationFailed):
            self.service.lock_for_decision("approver", "m1", " ")


class AccessTests(CustodyTestBase):
    def _approved_request(self) -> int:
        self.register()
        request = self.service.request_access(
            "op1", "m1", "律师张某", "13800001111", "事故处理程序规定第六十五条", "申诉阅卷"
        )
        self.service.decide_access("approver", request["request_id"], True, "同意", "2026-10-01T00:00:00Z")
        return request["request_id"]

    def test_full_legal_access_cycle(self) -> None:
        request_id = self._approved_request()
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM custody_materials WHERE material_id='m1'"
            ).fetchone()["state"],
            "access_pending",
        )
        self.service.checkout_access("op1", request_id, "登记出库")
        self.service.return_access("op1", request_id, "vault-1", "阅毕归还")
        material = self.connection.execute(
            "SELECT state,holder_user_id FROM custody_materials WHERE material_id='m1'"
        ).fetchone()
        self.assertEqual(material["state"], "stored")
        self.assertEqual(material["holder_user_id"], "op1")
        request_row = self.connection.execute(
            "SELECT state FROM custody_access_requests WHERE request_id=?", (request_id,)
        ).fetchone()
        self.assertEqual(request_row["state"], "returned")
        self.assertTrue(self.service.chain_view("auditor", "m1")["verification"]["intact"])

    def test_rejected_request_leaves_state_unchanged(self) -> None:
        self.register()
        request = self.service.request_access(
            "op1", "m1", "记者李某", "13900002222", "采访申请", "报道取材"
        )
        self.service.decide_access("approver", request["request_id"], False, "不属于法定调阅情形")
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM custody_materials WHERE material_id='m1'"
            ).fetchone()["state"],
            "sealed",
        )
        self.assertTrue(self.service.chain_view("auditor", "m1")["verification"]["intact"])

    def test_approved_request_can_expire_without_checkout(self) -> None:
        request_id = self._approved_request()
        self.service.expire_access("approver", request_id, "批准期限届满未领取")
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM custody_materials WHERE material_id='m1'"
            ).fetchone()["state"],
            "stored",
        )
        self.assertTrue(self.service.chain_view("auditor", "m1")["verification"]["intact"])

    def test_approval_requires_deadline(self) -> None:
        self.register()
        request = self.service.request_access(
            "op1", "m1", "律师张某", "13800001111", "法条", "阅卷"
        )
        with self.assertRaises(ValidationFailed):
            self.service.decide_access("approver", request["request_id"], True, "同意", None)
        with self.assertRaises(Forbidden):
            self.service.decide_access("op1", request["request_id"], False, "操作员无权审批")

    def test_approval_rejects_past_deadline_and_checkout_after_expiry(self) -> None:
        self.register()
        request = self.service.request_access(
            "op1", "m1", "律师张某", "13800001111", "法条", "阅卷"
        )
        with self.assertRaises(ValidationFailed):
            self.service.decide_access(
                "approver", request["request_id"], True, "同意", "2026-09-25T07:00:00Z"
            )
        self.service.decide_access(
            "approver", request["request_id"], True, "同意", "2026-09-25T09:00:00Z"
        )
        self.clock.advance(hours=2)
        with self.assertRaises(InvalidState):
            self.service.checkout_access("op1", request["request_id"], "超期出库")

    def test_second_request_blocked_while_first_open(self) -> None:
        self._approved_request()
        with self.assertRaises(InvalidState):
            self.service.request_access(
                "op1", "m1", "律师王某", "13700003333", "法条", "调阅未完结时再次申请"
            )

    def test_auditor_verification_permission(self) -> None:
        self.register()
        result = self.service.verification("auditor", "m1")
        self.assertTrue(result["intact"])
        with self.assertRaises(Forbidden):
            self.service.verification("op1", "m1")


class ContactMaskingTests(CustodyTestBase):
    def test_mask_contact_rules(self) -> None:
        self.assertEqual(mask_contact("13800001111"), "1*********1")
        self.assertEqual(mask_contact("12345"), "1****")
        self.assertEqual(mask_contact("12"), "1*")

    def test_contact_visibility_follows_role(self) -> None:
        self.register()
        request = self.service.request_access(
            "op1", "m1", "律师张某", "13800001111", "法条", "阅卷"
        )
        auditor_view = self.service.chain_view("auditor", "m1")
        op_view = self.service.chain_view("op1", "m1")
        stat_view = self.service.chain_view("stat", "m1")
        self.assertTrue(auditor_view["contact_visible"])
        self.assertEqual(auditor_view["access_requests"][0]["requester_contact"], "13800001111")
        self.assertFalse(op_view["contact_visible"])
        self.assertEqual(op_view["access_requests"][0]["requester_contact"], "1*********1")
        self.assertEqual(
            stat_view["events"][-1]["payload"]["requester_contact"], "1*********1"
        )
        # 原始存储不得被脱敏输出改动。
        self.assertEqual(
            self.connection.execute(
                "SELECT requester_contact FROM custody_access_requests WHERE request_id=?",
                (request["request_id"],),
            ).fetchone()["requester_contact"],
            "13800001111",
        )

    def test_statistician_without_read_permission_on_other_endpoints(self) -> None:
        self.register()
        with self.assertRaises(Forbidden):
            self.service.report_loss("stat", "m1", "无权")


class TamperDetectionTests(CustodyTestBase):
    def _mature_chain(self) -> None:
        self.register()
        self.transfer_to_op2()
        self.service.upload_version("op2", "m1", "f" * 64, PACKAGE_C, 2048, "补采")

    def test_intact_chain_reports_no_anomaly(self) -> None:
        self._mature_chain()
        result = verify_chain(self.connection, "m1")
        self.assertTrue(result["intact"])
        self.assertEqual(result["anomaly_count"], 0)

    def test_modified_event_payload_is_pinned_by_sequence(self) -> None:
        self._mature_chain()
        self.connection.execute(
            "UPDATE custody_events SET payload_json=? WHERE material_id='m1' AND sequence_no=2",
            (json.dumps({"tampered": True}, ensure_ascii=False),),
        )
        result = verify_chain(self.connection, "m1")
        self.assertFalse(result["intact"])
        mismatch = [a for a in result["anomalies"] if a["code"] == "hash_mismatch"]
        # 第 2 环负载被改后，其自校验重算哈希立刻不一致并定位到序号 2。
        self.assertEqual(len(mismatch), 1)
        self.assertEqual(mismatch[0]["sequence_no"], 2)
        self.assertIn("recomputed", mismatch[0])

    def test_deleted_event_breaks_sequence_and_tip(self) -> None:
        self._mature_chain()
        self.connection.execute("DELETE FROM custody_events WHERE material_id='m1' AND sequence_no=2")
        result = verify_chain(self.connection, "m1")
        codes = {a["code"] for a in result["anomalies"]}
        self.assertIn("chain_broken", codes)
        self.assertIn("chain_length_mismatch", codes)

    def test_version_digest_tampering_detected(self) -> None:
        self._mature_chain()
        self.connection.execute(
            "UPDATE custody_material_versions SET content_sha256=? WHERE material_id='m1' AND version_no=2",
            ("9" * 64,),
        )
        result = verify_chain(self.connection, "m1")
        digest = [a for a in result["anomalies"] if a["code"] == "digest_mismatch"]
        self.assertTrue(any(a.get("version_no") == 2 for a in digest))

    def test_material_state_drift_detected(self) -> None:
        self._mature_chain()
        self.connection.execute(
            "UPDATE custody_materials SET state='lost',holder_user_id=NULL WHERE material_id='m1'"
        )
        result = verify_chain(self.connection, "m1")
        codes = {a["code"]: a for a in result["anomalies"]}
        self.assertIn("state_drift", codes)
        self.assertIn("holder_drift", codes)

    def test_chain_tip_rewrite_detected(self) -> None:
        self._mature_chain()
        self.connection.execute(
            "UPDATE custody_materials SET last_event_hash=? WHERE material_id='m1'", ("0" * 64,)
        )
        result = verify_chain(self.connection, "m1")
        self.assertIn("chain_tip_mismatch", {a["code"] for a in result["anomalies"]})

    def test_post_lock_upload_flagged(self) -> None:
        self.register()
        self.service.lock_for_decision("approver", "m1", "认-1")
        # 绕过服务层直接插入一个锁定后的伪造版本事件（第 3 环）。
        material = self.connection.execute(
            "SELECT * FROM custody_materials WHERE material_id='m1'"
        ).fetchone()
        self.connection.execute(
            "INSERT INTO custody_material_versions(material_id,version_no,content_sha256,package_sha256,"
            "size_bytes,media_type,change_note,supersedes_version_no,created_by,created_at) "
            "VALUES('m1',2,?,?,512,'video/mp4','锁定后补版',1,'op1','2026-09-25T09:00:00Z')",
            ("f" * 64, PACKAGE_B),
        )
        self.connection.execute(
            "INSERT INTO custody_events(material_id,sequence_no,event_type,actor_id,state_after,"
            "payload_json,content_sha256,package_sha256,prev_hash,event_hash,created_at) "
            "VALUES('m1',3,'version.added','op1','stored',?,?,?,?,?,'2026-09-25T09:00:00Z')",
            (json.dumps({"version_no": 2}, ensure_ascii=False), "f" * 64, PACKAGE_B,
             material["last_event_hash"], "1" * 64),
        )
        result = verify_chain(self.connection, "m1")
        self.assertTrue(any(a["code"] == "post_lock_upload" for a in result["anomalies"]))


if __name__ == "__main__":
    unittest.main()
