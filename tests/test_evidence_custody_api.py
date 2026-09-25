from __future__ import annotations

import json
import sqlite3
import unittest

from evidence_custody.api import JsonApplication
from evidence_custody.service import EvidenceCustodyService


DIGEST_V1 = "1" * 64


class CustodyApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(EvidenceCustodyService(self.connection))

    def tearDown(self) -> None:
        self.connection.close()

    def _post(self, path: str, payload: dict, actor: str | None = None):
        headers = {"X-Actor-Id": actor} if actor else {}
        return self.app.handle("POST", path, headers, json.dumps(payload).encode("utf-8"))

    def _seed(self) -> None:
        self._post("/users", {"user_id": "collector", "display_name": "采集员", "role": "collector", "contact": "13800001111"})
        self._post("/users", {"user_id": "custodian", "display_name": "保管员", "role": "custodian", "contact": "13800002222"})
        self._post("/users", {"user_id": "officer", "display_name": "民警", "role": "case_officer", "contact": "13800003333"})
        self._post("/locations", {"location_id": "vault", "name": "证据库房", "kind": "warehouse"}, actor="custodian")
        self._post(
            "/packages",
            {
                "package_id": "pkg-1",
                "case_id": "case-1",
                "title": "现场证据包",
                "location_id": "vault",
                "content_sha256": DIGEST_V1,
                "note": "原始封存",
            },
            actor="collector",
        )

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_json_error_shape(self) -> None:
        response = self.app.handle("POST", "/users", body=b"not-json")
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_missing_actor_is_rejected(self) -> None:
        response = self._post("/locations", {"location_id": "vault", "name": "库房", "kind": "warehouse"})
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_full_route_flow(self) -> None:
        self._seed()
        handover = self._post(
            "/packages/pkg-1/handovers", {"to_user_id": "custodian", "to_location_id": "vault"}, actor="collector"
        )
        self.assertEqual(handover.status, 201)
        confirmed = self._post(
            f"/handovers/{handover.body['handover_id']}/confirm",
            {"accept": True, "received_digest": DIGEST_V1},
            actor="custodian",
        )
        self.assertEqual(confirmed.status, 200)
        self.assertEqual(confirmed.body["status"], "accepted")
        chain = self.app.handle("GET", "/packages/pkg-1/chain", {"X-Actor-Id": "officer"})
        self.assertEqual(chain.status, 200)
        self.assertEqual(chain.body["verification"]["status"], "intact")
        self.assertEqual(chain.body["package"]["current_holder"]["contact"], "13800002222")
        verify = self.app.handle("GET", "/packages/pkg-1/verify", {"X-Actor-Id": "custodian"})
        self.assertEqual(verify.status, 200)
        self.assertEqual(verify.body["event_count"], 2)
        forbidden = self.app.handle("GET", "/packages/pkg-1/chain", {"X-Actor-Id": "collector"})
        self.assertEqual(forbidden.status, 403)

    def test_unknown_route(self) -> None:
        response = self.app.handle("GET", "/nope")
        self.assertEqual(response.status, 404)
        self.assertEqual(response.body["error"]["code"], "route_not_found")


if __name__ == "__main__":
    unittest.main()
