from __future__ import annotations

import json
import sqlite3
import unittest

from evidence_review.api import JsonApplication
from evidence_review.service import EvidenceReviewService


class CustodyApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(EvidenceReviewService(self.connection))
        for user_id, role in (
            ("op1", "operator"), ("op2", "operator"),
            ("stat", "statistician"), ("approver", "approver"), ("auditor", "auditor"),
        ):
            self.app.handle("POST", "/users", body=json.dumps(
                {"user_id": user_id, "display_name": user_id, "role": role}).encode())
        self.app.handle("POST", "/custody/locations", body=json.dumps(
            {"location_id": "v1", "label": "库房", "kind": "vault"}).encode(),
            headers={"X-Actor-Id": "op1"})

    def tearDown(self) -> None:
        self.connection.close()

    def _call(self, method: str, path: str, payload: dict | None = None, actor: str = "op1"):
        body = json.dumps(payload or {}).encode("utf-8")
        return self.app.handle(method, path, {"X-Actor-Id": actor, "Content-Type": "application/json"}, body)

    def _register(self) -> None:
        response = self._call("POST", "/custody/materials", {
            "material_id": "m1", "title": "现场视频", "material_type": "video",
            "location_id": "v1", "content_sha256": "a" * 64, "package_sha256": "b" * 64,
            "size_bytes": 1024, "media_type": "video/mp4", "note": "首版",
        })
        self.assertEqual(response.status, 201, response.body)

    def test_requires_actor_header(self) -> None:
        response = self.app.handle("GET", "/custody/materials")
        self.assertEqual(response.status, 422)

    def test_register_and_chain_view_end_to_end(self) -> None:
        self._register()
        response = self._call("GET", "/custody/materials/m1/chain", actor="auditor")
        self.assertEqual(response.status, 200)
        self.assertTrue(response.body["verification"]["intact"])
        self.assertEqual(response.body["events"][0]["event_type"], "material.registered")
        self.assertEqual(len(response.body["events"][0]["event_hash"]), 64)

    def test_transfer_accept_and_reject_flow(self) -> None:
        self._register()
        proposed = self._call("POST", "/custody/materials/m1/transfers", {
            "to_user_id": "op2", "to_location_id": "v1", "purpose": "移交",
        })
        self.assertEqual(proposed.status, 201)
        transfer_id = proposed.body["transfer_id"]
        accepted = self._call("POST", f"/custody/transfers/{transfer_id}/respond", {
            "accept": True, "note": "完好",
        }, actor="op2")
        self.assertEqual(accepted.status, 200)
        self.assertEqual(accepted.body["state"], "accepted")

    def test_contact_masked_for_operator_visible_to_auditor(self) -> None:
        self._register()
        self._call("POST", "/custody/materials/m1/access_requests", {
            "requester_name": "律师张某", "requester_contact": "13800001111",
            "legal_basis": "事故处理程序规定", "purpose": "阅卷",
        })
        masked = self._call("GET", "/custody/materials/m1/chain", actor="op2")
        visible = self._call("GET", "/custody/materials/m1/chain", actor="auditor")
        self.assertEqual(masked.body["access_requests"][0]["requester_contact"], "1*********1")
        self.assertEqual(visible.body["access_requests"][0]["requester_contact"], "13800001111")

    def test_locked_material_rejects_upload_with_409(self) -> None:
        self._register()
        locked = self._call("POST", "/custody/materials/m1/lock", {
            "decision_reference": "认-2026-001",
        }, actor="approver")
        self.assertEqual(locked.status, 200)
        response = self._call("POST", "/custody/materials/m1/versions", {
            "content_sha256": "f" * 64, "package_sha256": "c" * 64,
            "size_bytes": 1, "change_note": "试图覆盖",
        })
        self.assertEqual(response.status, 409)
        self.assertEqual(response.body["error"]["code"], "invalid_state")

    def test_role_forbidden_maps_to_403(self) -> None:
        self._register()
        response = self._call("POST", "/custody/materials", {
            "material_id": "m2", "title": "x", "material_type": "doc",
            "location_id": "v1", "content_sha256": "a" * 64, "package_sha256": "b" * 64,
            "size_bytes": 1, "media_type": "text/plain",
        }, actor="stat")
        self.assertEqual(response.status, 403)

    def test_list_materials_filtered_by_batch(self) -> None:
        self._register()
        response = self._call("GET", "/custody/materials?batch_id=batch-x", actor="auditor")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["materials"], [])


if __name__ == "__main__":
    unittest.main()
