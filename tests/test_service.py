from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path

from evidence_review.clock import FrozenClock
from evidence_review.custody import CustodyService
from evidence_review.errors import Conflict, Forbidden, InvalidState
from evidence_review.jsonio import load_json
from evidence_review.service import EvidenceReviewService


ROOT = Path(__file__).resolve().parents[1]


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = EvidenceReviewService(self.connection, self.clock)
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("approver", "approver"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.evidence_protocol = load_json(ROOT / "fixtures" / "demo_evidence_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_evidence_items.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.service.register_device("operator", "device-a", "A 型", "厂商")
        self.service.register_build("operator", "build-a", "device-a", "1.0", "b" * 64)
        self.service.publish_evidence_protocol("stat", self.evidence_protocol)
        self.service.create_batch("operator", "batch-a", "demo-evidence-v1", 1, "build-a")
        self.service.start_batch("operator", "batch-a", 1)

    def tearDown(self) -> None:
        self.connection.close()

    def test_complete_workflow(self) -> None:
        imported = self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        self.assertEqual(imported["inserted"], 6)
        self.service.seal_batch("stat", "batch-a", 2)
        job = self.service.claim_job("worker", 30)
        analysis = self.service.complete_job("worker", job["job_id"], "stat")
        self.service.decide("approver", "batch-a", analysis["analysis_id"], "approved", "满足规则")
        report = self.service.report("auditor", "batch-a")
        self.assertEqual(report["batch"]["state"], "decided")
        self.assertEqual(report["analysis"]["result"]["conclusion"], "pass")

    def test_idempotent_replay_and_conflict(self) -> None:
        first = self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        second = self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        self.assertEqual(first, second)
        changed = [dict(item) for item in self.rows]
        changed[0] = dict(changed[0])
        changed[0]["indicators"] = dict(changed[0]["indicators"])
        changed[0]["indicators"]["completion_seconds"] = "99"
        with self.assertRaises(Conflict):
            self.service.import_evidence_items("operator", "batch-a", "key-1", changed)
        count = self.connection.execute("SELECT count(*) FROM evidence_items").fetchone()[0]
        self.assertEqual(count, 6)

    def test_import_rolls_back_when_one_source_row_duplicates(self) -> None:
        self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows[:1])
        with self.assertRaises(Conflict):
            self.service.import_evidence_items("operator", "batch-a", "key-2", self.rows[:2])
        count = self.connection.execute("SELECT count(*) FROM evidence_items").fetchone()[0]
        self.assertEqual(count, 1)

    def test_role_separation(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.seal_batch("operator", "batch-a", 2)
        with self.assertRaises(Forbidden):
            self.service.report("operator", "batch-a")

    def test_exclusion_review_and_revoke_leave_history(self) -> None:
        self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        evidence_item_id = self.connection.execute(
            "SELECT evidence_item_id FROM evidence_items ORDER BY evidence_item_id LIMIT 1"
        ).fetchone()[0]
        requested = self.service.request_exclusion("operator", evidence_item_id, "现场记录失效")
        reviewed = self.service.review_exclusion("stat", requested["exclusion_id"], True, "证据充分")
        self.assertEqual(reviewed["status"], "approved")
        revoked = self.service.revoke_exclusion("operator", requested["exclusion_id"], "已找回原始记录")
        self.assertEqual(revoked["status"], "revoked")
        events = self.connection.execute(
            "SELECT event_type FROM audit_events WHERE entity_type='evidence_item' AND entity_id=? ORDER BY event_id",
            (str(evidence_item_id),),
        ).fetchall()
        self.assertEqual([row[0] for row in events], ["exclusion.requested", "exclusion.revoked"])

    def test_failed_job_returns_to_queue_after_delay(self) -> None:
        self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        self.service.seal_batch("stat", "batch-a", 2)
        job = self.service.claim_job("worker-a", 10)
        failed = self.service.fail_job("worker-a", job["job_id"], "临时计算失败", retry_seconds=5)
        self.assertEqual(failed["state"], "queued")
        self.assertIsNone(self.service.claim_job("worker-b", 10))
        self.clock.advance(seconds=5)
        retried = self.service.claim_job("worker-b", 10)
        self.assertEqual(retried["job_id"], job["job_id"])
        self.assertEqual(retried["attempts"], 2)

    def test_lease_can_be_reclaimed_after_expiry(self) -> None:
        self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        self.service.seal_batch("stat", "batch-a", 2)
        first = self.service.claim_job("worker-a", 10)
        self.clock.advance(seconds=11)
        second = self.service.claim_job("worker-b", 10)
        self.assertEqual(first["job_id"], second["job_id"])
        self.assertEqual(second["lease_owner"], "worker-b")
        with self.assertRaises(InvalidState):
            self.service.complete_job("worker-a", first["job_id"], "stat")

    def _analyzed_batch(self) -> int:
        self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        self.service.seal_batch("stat", "batch-a", 2)
        job = self.service.claim_job("worker", 30)
        analysis = self.service.complete_job("worker", job["job_id"], "stat")
        return analysis["analysis_id"]

    def test_decision_locks_batch_custody_materials(self) -> None:
        analysis_id = self._analyzed_batch()
        custody = CustodyService(self.connection, self.clock)
        custody.register_location("operator", "vault-1", "库房", "vault")
        custody.register_material(
            "operator", "mat-1", "原始视频", "video", "vault-1",
            "a" * 64, "b" * 64, 1024, "video/mp4", "首版", batch_id="batch-a",
        )
        result = self.service.decide("approver", "batch-a", analysis_id, "approved", "采信")
        self.assertEqual(result["locked_materials"], 1)
        self.assertTrue(
            self.connection.execute(
                "SELECT locked_for_decision FROM custody_materials WHERE material_id='mat-1'"
            ).fetchone()[0]
        )
        with self.assertRaises(InvalidState):
            custody.upload_version("operator", "mat-1", "c" * 64, "d" * 64, 1, "认定后补传")
        report = self.service.report("auditor", "batch-a")
        self.assertEqual(len(report["custody_materials"]), 1)
        self.assertTrue(report["custody_materials"][0]["chain_intact"])
        self.assertTrue(report["custody_materials"][0]["locked_for_decision"])

    def test_decision_refused_when_custody_chain_tampered(self) -> None:
        analysis_id = self._analyzed_batch()
        custody = CustodyService(self.connection, self.clock)
        custody.register_location("operator", "vault-1", "库房", "vault")
        custody.register_material(
            "operator", "mat-1", "原始视频", "video", "vault-1",
            "a" * 64, "b" * 64, 1024, "video/mp4", "首版", batch_id="batch-a",
        )
        # 直接篡改链事件，模拟材料被动过。
        self.connection.execute(
            "UPDATE custody_events SET payload_json='{\"tampered\":true}' "
            "WHERE material_id='mat-1' AND sequence_no=1"
        )
        with self.assertRaises(InvalidState):
            self.service.decide("approver", "batch-a", analysis_id, "approved", "采信")
        # 决定不得写入，批次保持 analyzed。
        self.assertEqual(
            self.connection.execute("SELECT state FROM batches WHERE batch_id='batch-a'").fetchone()[0],
            "analyzed",
        )

    def test_needs_more_data_decision_does_not_lock_materials(self) -> None:
        analysis_id = self._analyzed_batch()
        custody = CustodyService(self.connection, self.clock)
        custody.register_location("operator", "vault-1", "库房", "vault")
        custody.register_material(
            "operator", "mat-1", "原始视频", "video", "vault-1",
            "a" * 64, "b" * 64, 1024, "video/mp4", "首版", batch_id="batch-a",
        )
        result = self.service.decide(
            "approver", "batch-a", analysis_id, "needs_more_data", "需补充材料"
        )
        self.assertEqual(result["locked_materials"], 0)
        self.assertFalse(
            self.connection.execute(
                "SELECT locked_for_decision FROM custody_materials WHERE material_id='mat-1'"
            ).fetchone()[0]
        )
        # 非终局决定后仍可上传新版本。
        custody.upload_version("operator", "mat-1", "c" * 64, "d" * 64, 1, "补充版本")


if __name__ == "__main__":
    unittest.main()
