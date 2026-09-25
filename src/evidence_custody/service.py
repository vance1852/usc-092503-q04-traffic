"""证据材料保全链、交接确认与责任认定版本锁定的领域用例。"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Mapping

from .clock import SystemClock, isoformat
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


GENESIS_HASH = "0" * 64

HANDOVER_ROLES = frozenset({"collector", "custodian", "case_officer", "reviewer"})

ROLE_PERMISSIONS = {
    "collector": {"package.register", "version.upload", "package.reseal"},
    "custodian": {"location.write", "package.reseal", "chain.read"},
    "case_officer": {"package.retrieve", "determination.write", "chain.read", "contact.read"},
    "reviewer": {"package.retrieve", "chain.read"},
    "auditor": {"chain.read", "audit.read"},
}

LOCATION_KINDS = frozenset({"warehouse", "cabinet", "electronic"})

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def mask_contact(contact: str) -> str:
    """对联系方式做确定性遮蔽，低权限角色只能看到遮蔽后的形式。"""

    if contact.isdigit() and len(contact) >= 7:
        return f"{contact[:3]}****{contact[-4:]}"
    if len(contact) > 1:
        return contact[0] + "***"
    return "*"


def _check_digest(value: object, field: str = "内容摘要") -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in _HEX_DIGITS for char in value):
        raise ValidationFailed(f"{field}必须是 64 位十六进制 SHA-256")
    return value.lower()


def _transition(event_type: str, status: str | None) -> tuple[bool, str | None]:
    """保全链状态机：返回 (事件是否允许出现在当前状态之后, 事件完成后的保管状态)。"""

    if event_type == "register":
        return status is None, "sealed"
    if event_type == "version_upload":
        return status in ("sealed", "out_on_retrieval"), status
    if event_type == "handover":
        return status in ("sealed", "out_on_retrieval"), "sealed"
    if event_type == "reject":
        return status is not None, status
    if event_type == "loss":
        return status in ("sealed", "out_on_retrieval"), "lost"
    if event_type == "reseal":
        return status in ("sealed", "lost"), "sealed"
    if event_type == "retrieve":
        return status == "sealed", "out_on_retrieval"
    if event_type == "determination":
        return status is not None, status
    return False, status


class EvidenceCustodyService:
    """在单个 SQLite 连接上提供证据保全链的全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, display_name, role, contact, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _require_handover_party(self, user_id: str) -> sqlite3.Row:
        user = self._user(user_id)
        if user["role"] not in HANDOVER_ROLES:
            raise Forbidden(f"角色 {user['role']} 不在交接限定角色内")
        return user

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, canonical_json(payload), self._now()),
        )

    def _location(self, location_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT location_id, name, kind FROM storage_locations WHERE location_id=?", (location_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"保管位置不存在: {location_id}")
        return row

    def _package(self, package_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM evidence_packages WHERE package_id=?", (package_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"证据包不存在: {package_id}")
        return row

    def _version(self, package_id: str, version_no: int) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM evidence_versions WHERE package_id=? AND version_no=?",
            (package_id, version_no),
        ).fetchone()
        if row is None:
            raise NotFound(f"证据包 {package_id} 不存在版本 {version_no}")
        return row

    def _pending_handover(self, package_id: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM handovers WHERE package_id=? AND status='pending'", (package_id,)
        ).fetchone()

    def create_user(self, user_id: str, display_name: str, role: str, contact: str) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知角色: {role}")
        for label, value in (("用户编号", user_id), ("用户名称", display_name), ("联系方式", contact)):
            if not isinstance(value, str) or not value.strip():
                raise ValidationFailed(f"{label}不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name,role,contact) VALUES(?,?,?,?)",
                    (user_id.strip(), display_name.strip(), role, contact.strip()),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip(), "role": role}

    def register_location(self, actor_id: str, location_id: str, name: str, kind: str) -> dict[str, Any]:
        self._require(actor_id, "location.write")
        if kind not in LOCATION_KINDS:
            raise ValidationFailed(f"未知保管位置类型: {kind}")
        if not location_id.strip() or not name.strip():
            raise ValidationFailed("保管位置编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO storage_locations(location_id,name,kind,created_at) VALUES(?,?,?,?)",
                    (location_id.strip(), name.strip(), kind, self._now()),
                )
                self._audit(
                    "location", location_id.strip(), "location.registered", actor_id,
                    {"name": name.strip(), "kind": kind},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"保管位置已存在: {location_id}") from exc
        return {"location_id": location_id.strip(), "name": name.strip(), "kind": kind}

    def _append_event(
        self,
        package_id: str,
        event_type: str,
        actor_id: str,
        *,
        version_no: int | None = None,
        digest: str | None = None,
        from_user_id: str | None = None,
        to_user_id: str | None = None,
        location_id: str | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """在事务内向保全链追加一环，并用前向哈希与上一环衔接。"""

        tail = self.connection.execute(
            "SELECT seq, event_hash FROM custody_events WHERE package_id=? ORDER BY seq DESC LIMIT 1",
            (package_id,),
        ).fetchone()
        seq = 1 if tail is None else tail["seq"] + 1
        prev_hash = GENESIS_HASH if tail is None else tail["event_hash"]
        detail_json = canonical_json(detail or {})
        created_at = self._now()
        payload = {
            "package_id": package_id,
            "seq": seq,
            "event_type": event_type,
            "version_no": version_no,
            "content_sha256": digest,
            "from_user_id": from_user_id,
            "to_user_id": to_user_id,
            "location_id": location_id,
            "actor_id": actor_id,
            "detail_json": detail_json,
            "prev_event_hash": prev_hash,
            "created_at": created_at,
        }
        event_hash = content_digest([payload])
        cursor = self.connection.execute(
            "INSERT INTO custody_events(package_id,seq,event_type,version_no,content_sha256,from_user_id,to_user_id,"
            "location_id,actor_id,detail_json,prev_event_hash,event_hash,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                package_id, seq, event_type, version_no, digest, from_user_id, to_user_id,
                location_id, actor_id, detail_json, prev_hash, event_hash, created_at,
            ),
        )
        return {"event_id": cursor.lastrowid, "seq": seq, "event_hash": event_hash}

    def register_package(
        self,
        actor_id: str,
        package_id: str,
        case_id: str,
        title: str,
        location_id: str,
        content_sha256: str,
        note: str = "",
    ) -> dict[str, Any]:
        """登记证据包并封存首个版本，生成保全链的创世环节。"""

        self._require(actor_id, "package.register")
        self._location(location_id)
        digest = _check_digest(content_sha256)
        if not package_id.strip() or not case_id.strip() or not title.strip():
            raise ValidationFailed("证据包编号、案件编号和名称不能为空")
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO evidence_packages(package_id,case_id,title,custody_status,current_holder_id,"
                    "current_location_id,current_version_no,revision,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        package_id.strip(), case_id.strip(), title.strip(), "sealed",
                        actor_id, location_id, 1, 1, actor_id, now,
                    ),
                )
                self.connection.execute(
                    "INSERT INTO evidence_versions(package_id,version_no,content_sha256,note,uploaded_by,uploaded_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (package_id.strip(), 1, digest, note, actor_id, now),
                )
                event = self._append_event(
                    package_id.strip(), "register", actor_id,
                    version_no=1, digest=digest, to_user_id=actor_id, location_id=location_id,
                    detail={"note": note, "case_id": case_id.strip(), "title": title.strip()},
                )
                self._audit(
                    "package", package_id.strip(), "package.registered", actor_id,
                    {"case_id": case_id.strip(), "sha256": digest, "seq": event["seq"]},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"证据包已存在: {package_id}") from exc
        return {
            "package_id": package_id.strip(),
            "version_no": 1,
            "content_sha256": digest,
            "event_seq": event["seq"],
        }

    def upload_version(
        self, actor_id: str, package_id: str, content_sha256: str, note: str = ""
    ) -> dict[str, Any]:
        """追加新版本。版本行只增不改：已用于责任认定的版本永远不会被后续上传覆盖。"""

        self._require(actor_id, "version.upload")
        package = self._package(package_id)
        digest = _check_digest(content_sha256)
        if package["custody_status"] == "lost":
            raise InvalidState("证据包处于遗失状态，不能上传新版本")
        if self._pending_handover(package_id) is not None:
            raise InvalidState("证据包存在待确认交接，不能上传新版本")
        next_no = package["current_version_no"] + 1
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "INSERT INTO evidence_versions(package_id,version_no,content_sha256,note,uploaded_by,uploaded_at) "
                "VALUES(?,?,?,?,?,?)",
                (package_id, next_no, digest, note, actor_id, self._now()),
            )
            cursor = self.connection.execute(
                "UPDATE evidence_packages SET current_version_no=?,revision=revision+1 "
                "WHERE package_id=? AND current_version_no=?",
                (next_no, package_id, package["current_version_no"]),
            )
            if cursor.rowcount != 1:
                raise InvalidState("证据包版本已变化")
            event = self._append_event(
                package_id, "version_upload", actor_id,
                version_no=next_no, digest=digest, detail={"note": note},
            )
            self._audit(
                "package", package_id, "version.uploaded", actor_id,
                {"version_no": next_no, "sha256": digest, "seq": event["seq"]},
            )
        return {
            "package_id": package_id,
            "version_no": next_no,
            "content_sha256": digest,
            "event_seq": event["seq"],
        }

    def initiate_handover(
        self, actor_id: str, package_id: str, to_user_id: str, to_location_id: str, note: str = ""
    ) -> dict[str, Any]:
        """当前保管人发起交接，接收人必须在限定角色内，交接单快照当前版本摘要。"""

        self._require_handover_party(actor_id)
        self._require_handover_party(to_user_id)
        if to_user_id == actor_id:
            raise ValidationFailed("交接双方不能是同一人")
        self._location(to_location_id)
        package = self._package(package_id)
        if package["current_holder_id"] != actor_id:
            raise Forbidden("只有当前保管人可以发起交接")
        if package["custody_status"] == "lost":
            raise InvalidState("证据包处于遗失状态，不能交接")
        version = self._version(package_id, package["current_version_no"])
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO handovers(package_id,from_user_id,to_user_id,to_location_id,version_no,"
                    "content_sha256,status,note,initiated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        package_id, actor_id, to_user_id, to_location_id,
                        package["current_version_no"], version["content_sha256"],
                        "pending", note, self._now(),
                    ),
                )
                handover_id = cursor.lastrowid
                self._audit(
                    "package", package_id, "handover.initiated", actor_id,
                    {"handover_id": handover_id, "to_user_id": to_user_id},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("证据包已存在待确认交接") from exc
        return {
            "handover_id": handover_id,
            "status": "pending",
            "version_no": package["current_version_no"],
            "content_sha256": version["content_sha256"],
        }

    def confirm_handover(
        self,
        actor_id: str,
        handover_id: int,
        accept: bool,
        received_digest: str | None = None,
        reason: str = "",
    ) -> dict[str, Any]:
        """接收人在限定角色内确认交接；接收摘要不符时必须拒收。"""

        self._require_handover_party(actor_id)
        handover = self.connection.execute(
            "SELECT * FROM handovers WHERE handover_id=?", (handover_id,)
        ).fetchone()
        if handover is None:
            raise NotFound("交接单不存在")
        if handover["status"] != "pending":
            raise InvalidState("交接单已经处理")
        if handover["to_user_id"] != actor_id:
            raise Forbidden("只有指定接收人可以确认交接")
        package = self._package(handover["package_id"])
        now = self._now()
        if accept:
            digest = _check_digest(received_digest, "接收摘要")
            if digest != handover["content_sha256"]:
                raise ValidationFailed("接收摘要与登记摘要不一致，应当拒收并上报")
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "UPDATE handovers SET status='accepted',resolved_at=? WHERE handover_id=? AND status='pending'",
                    (now, handover_id),
                )
                if cursor.rowcount != 1:
                    raise InvalidState("交接单状态已变化")
                self.connection.execute(
                    "UPDATE evidence_packages SET current_holder_id=?,current_location_id=?,"
                    "custody_status='sealed',revision=revision+1 WHERE package_id=?",
                    (actor_id, handover["to_location_id"], package["package_id"]),
                )
                event = self._append_event(
                    package["package_id"], "handover", actor_id,
                    version_no=handover["version_no"], digest=handover["content_sha256"],
                    from_user_id=handover["from_user_id"], to_user_id=actor_id,
                    location_id=handover["to_location_id"],
                    detail={"handover_id": handover_id, "note": handover["note"]},
                )
                self._audit(
                    "package", package["package_id"], "handover.accepted", actor_id,
                    {"handover_id": handover_id},
                )
            return {"handover_id": handover_id, "status": "accepted", "event_seq": event["seq"]}
        if not reason.strip():
            raise ValidationFailed("拒收必须说明原因")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE handovers SET status='rejected',reject_reason=?,resolved_at=? "
                "WHERE handover_id=? AND status='pending'",
                (reason.strip(), now, handover_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("交接单状态已变化")
            event = self._append_event(
                package["package_id"], "reject", actor_id,
                version_no=handover["version_no"], digest=handover["content_sha256"],
                from_user_id=handover["from_user_id"], to_user_id=actor_id,
                location_id=handover["to_location_id"],
                detail={"handover_id": handover_id, "reason": reason.strip()},
            )
            self._audit(
                "package", package["package_id"], "handover.rejected", actor_id,
                {"handover_id": handover_id, "reason": reason.strip()},
            )
        return {"handover_id": handover_id, "status": "rejected", "event_seq": event["seq"]}

    def report_loss(self, actor_id: str, package_id: str, detail: str) -> dict[str, Any]:
        """当前保管人报告遗失，保全链进入遗失状态。"""

        self._require_handover_party(actor_id)
        if not detail.strip():
            raise ValidationFailed("遗失报告必须说明情况")
        package = self._package(package_id)
        if package["current_holder_id"] != actor_id:
            raise Forbidden("只有当前保管人可以报告遗失")
        if package["custody_status"] == "lost":
            raise InvalidState("证据包已处于遗失状态")
        if self._pending_handover(package_id) is not None:
            raise InvalidState("证据包存在待确认交接，不能报告遗失")
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE evidence_packages SET custody_status='lost',revision=revision+1 WHERE package_id=?",
                (package_id,),
            )
            event = self._append_event(
                package_id, "loss", actor_id, from_user_id=actor_id,
                detail={"note": detail.strip()},
            )
            self._audit("package", package_id, "loss.reported", actor_id, {"note": detail.strip()})
        return {"package_id": package_id, "custody_status": "lost", "event_seq": event["seq"]}

    def reseal_package(
        self, actor_id: str, package_id: str, content_sha256: str, location_id: str, note: str = ""
    ) -> dict[str, Any]:
        """重新封装并形成新版本；遗失找回后也通过重新封装回到在库封存状态。"""

        self._require(actor_id, "package.reseal")
        self._location(location_id)
        package = self._package(package_id)
        digest = _check_digest(content_sha256)
        if package["custody_status"] == "out_on_retrieval":
            raise InvalidState("证据包正在依法调阅中，不能重新封装")
        if self._pending_handover(package_id) is not None:
            raise InvalidState("证据包存在待确认交接，不能重新封装")
        next_no = package["current_version_no"] + 1
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "INSERT INTO evidence_versions(package_id,version_no,content_sha256,note,uploaded_by,uploaded_at) "
                "VALUES(?,?,?,?,?,?)",
                (package_id, next_no, digest, note, actor_id, self._now()),
            )
            self.connection.execute(
                "UPDATE evidence_packages SET custody_status='sealed',current_holder_id=?,current_location_id=?,"
                "current_version_no=?,revision=revision+1 WHERE package_id=?",
                (actor_id, location_id, next_no, package_id),
            )
            event = self._append_event(
                package_id, "reseal", actor_id,
                version_no=next_no, digest=digest, to_user_id=actor_id, location_id=location_id,
                detail={"note": note, "recovered": package["custody_status"] == "lost"},
            )
            self._audit(
                "package", package_id, "package.resealed", actor_id,
                {"version_no": next_no, "sha256": digest},
            )
        return {
            "package_id": package_id,
            "version_no": next_no,
            "custody_status": "sealed",
            "event_seq": event["seq"],
        }

    def retrieve_package(
        self, actor_id: str, package_id: str, legal_doc_no: str, purpose: str
    ) -> dict[str, Any]:
        """依法调阅：必须登记法律文书编号和用途，保管人转为调阅人。"""

        self._require(actor_id, "package.retrieve")
        if not legal_doc_no.strip() or not purpose.strip():
            raise ValidationFailed("依法调阅必须登记法律文书编号和用途")
        package = self._package(package_id)
        if package["custody_status"] != "sealed":
            raise InvalidState("只有在库封存的证据包可以调阅")
        if self._pending_handover(package_id) is not None:
            raise InvalidState("证据包存在待确认交接，不能调阅")
        version = self._version(package_id, package["current_version_no"])
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE evidence_packages SET custody_status='out_on_retrieval',current_holder_id=?,"
                "current_location_id=NULL,revision=revision+1 WHERE package_id=?",
                (actor_id, package_id),
            )
            event = self._append_event(
                package_id, "retrieve", actor_id,
                version_no=package["current_version_no"], digest=version["content_sha256"],
                to_user_id=actor_id,
                detail={"legal_doc_no": legal_doc_no.strip(), "purpose": purpose.strip()},
            )
            self._audit(
                "package", package_id, "package.retrieved", actor_id,
                {"legal_doc_no": legal_doc_no.strip()},
            )
        return {"package_id": package_id, "custody_status": "out_on_retrieval", "event_seq": event["seq"]}

    def record_determination(
        self, actor_id: str, package_id: str, version_no: int, summary: str
    ) -> dict[str, Any]:
        """登记责任认定并锁定所依据的版本摘要，该版本此后不得被上传覆盖。"""

        self._require(actor_id, "determination.write")
        if not summary.strip():
            raise ValidationFailed("责任认定结论不能为空")
        self._package(package_id)
        version = self._version(package_id, int(version_no))
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO liability_determinations(package_id,version_no,content_sha256,summary,"
                    "decided_by,decided_at) VALUES(?,?,?,?,?,?)",
                    (
                        package_id, version["version_no"], version["content_sha256"],
                        summary.strip(), actor_id, self._now(),
                    ),
                )
                determination_id = cursor.lastrowid
                event = self._append_event(
                    package_id, "determination", actor_id,
                    version_no=version["version_no"], digest=version["content_sha256"],
                    detail={"determination_id": determination_id, "summary": summary.strip()},
                )
                self._audit(
                    "package", package_id, "determination.recorded", actor_id,
                    {"determination_id": determination_id, "version_no": version["version_no"]},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"版本 {version_no} 已经用于责任认定") from exc
        return {
            "determination_id": determination_id,
            "package_id": package_id,
            "version_no": version["version_no"],
            "content_sha256": version["content_sha256"],
        }

    def _user_payload(self, user_id: str | None, reveal_contact: bool) -> dict[str, Any] | None:
        if user_id is None:
            return None
        row = self.connection.execute(
            "SELECT user_id, display_name, role, contact FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            return {"user_id": user_id, "display_name": None, "role": None, "contact": None}
        return {
            "user_id": row["user_id"],
            "display_name": row["display_name"],
            "role": row["role"],
            "contact": row["contact"] if reveal_contact else mask_contact(row["contact"]),
        }

    def _location_payload(self, location_id: str | None) -> dict[str, Any] | None:
        if location_id is None:
            return None
        row = self.connection.execute(
            "SELECT location_id, name, kind FROM storage_locations WHERE location_id=?", (location_id,)
        ).fetchone()
        return None if row is None else dict(row)

    def get_chain(self, actor_id: str, package_id: str) -> dict[str, Any]:
        """展示完整保全链；联系方式等敏感信息按角色权限遮蔽。"""

        user = self._require(actor_id, "chain.read")
        reveal = "contact.read" in ROLE_PERMISSIONS[user["role"]]
        package = self._package(package_id)
        versions = self.connection.execute(
            "SELECT v.*, (d.determination_id IS NOT NULL) AS locked FROM evidence_versions v "
            "LEFT JOIN liability_determinations d ON d.package_id=v.package_id AND d.version_no=v.version_no "
            "WHERE v.package_id=? ORDER BY v.version_no",
            (package_id,),
        ).fetchall()
        handovers = self.connection.execute(
            "SELECT * FROM handovers WHERE package_id=? ORDER BY handover_id", (package_id,)
        ).fetchall()
        events = self.connection.execute(
            "SELECT * FROM custody_events WHERE package_id=? ORDER BY seq", (package_id,)
        ).fetchall()
        determinations = self.connection.execute(
            "SELECT * FROM liability_determinations WHERE package_id=? ORDER BY determination_id",
            (package_id,),
        ).fetchall()
        return {
            "package": {
                "package_id": package["package_id"],
                "case_id": package["case_id"],
                "title": package["title"],
                "custody_status": package["custody_status"],
                "current_holder": self._user_payload(package["current_holder_id"], reveal),
                "current_location": self._location_payload(package["current_location_id"]),
                "current_version_no": package["current_version_no"],
                "created_at": package["created_at"],
            },
            "versions": [
                {
                    "version_no": row["version_no"],
                    "content_sha256": row["content_sha256"],
                    "note": row["note"],
                    "uploaded_by": self._user_payload(row["uploaded_by"], reveal),
                    "uploaded_at": row["uploaded_at"],
                    "locked_by_determination": bool(row["locked"]),
                }
                for row in versions
            ],
            "handovers": [
                {
                    "handover_id": row["handover_id"],
                    "from_user": self._user_payload(row["from_user_id"], reveal),
                    "to_user": self._user_payload(row["to_user_id"], reveal),
                    "to_location": self._location_payload(row["to_location_id"]),
                    "version_no": row["version_no"],
                    "content_sha256": row["content_sha256"],
                    "status": row["status"],
                    "note": row["note"],
                    "reject_reason": row["reject_reason"],
                    "initiated_at": row["initiated_at"],
                    "resolved_at": row["resolved_at"],
                }
                for row in handovers
            ],
            "events": [
                {
                    "seq": row["seq"],
                    "event_type": row["event_type"],
                    "version_no": row["version_no"],
                    "content_sha256": row["content_sha256"],
                    "from_user": self._user_payload(row["from_user_id"], reveal),
                    "to_user": self._user_payload(row["to_user_id"], reveal),
                    "location": self._location_payload(row["location_id"]),
                    "actor": self._user_payload(row["actor_id"], reveal),
                    "detail": json.loads(row["detail_json"]),
                    "prev_event_hash": row["prev_event_hash"],
                    "event_hash": row["event_hash"],
                    "created_at": row["created_at"],
                }
                for row in events
            ],
            "determinations": [
                {
                    "determination_id": row["determination_id"],
                    "version_no": row["version_no"],
                    "content_sha256": row["content_sha256"],
                    "summary": row["summary"],
                    "decided_by": self._user_payload(row["decided_by"], reveal),
                    "decided_at": row["decided_at"],
                }
                for row in determinations
            ],
            "contacts_masked": not reveal,
            "verification": self._verify(package_id),
        }

    def verify_chain(self, actor_id: str, package_id: str) -> dict[str, Any]:
        """重放保全链，指出链条断裂或摘要不一致的具体环节。"""

        self._require(actor_id, "chain.read")
        self._package(package_id)
        return self._verify(package_id)

    def _verify(self, package_id: str) -> dict[str, Any]:
        package = self._package(package_id)
        events = self.connection.execute(
            "SELECT * FROM custody_events WHERE package_id=? ORDER BY seq", (package_id,)
        ).fetchall()
        breaks: list[dict[str, Any]] = []
        expected_seq = 1
        prev_hash = GENESIS_HASH
        status: str | None = None
        holder: str | None = None
        location: str | None = None
        current_version = 0
        for event in events:
            position = {"seq": event["seq"], "event_id": event["event_id"]}
            if event["seq"] != expected_seq:
                breaks.append({
                    **position,
                    "kind": "sequence_gap",
                    "detail": f"链条序号断裂：期望第 {expected_seq} 环，实际第 {event['seq']} 环",
                })
                expected_seq = event["seq"]
            if event["prev_event_hash"] != prev_hash:
                breaks.append({
                    **position,
                    "kind": "prev_hash_mismatch",
                    "detail": "前向哈希与上一环不一致，中间环节可能被删除或替换",
                })
            payload = {
                "package_id": event["package_id"],
                "seq": event["seq"],
                "event_type": event["event_type"],
                "version_no": event["version_no"],
                "content_sha256": event["content_sha256"],
                "from_user_id": event["from_user_id"],
                "to_user_id": event["to_user_id"],
                "location_id": event["location_id"],
                "actor_id": event["actor_id"],
                "detail_json": event["detail_json"],
                "prev_event_hash": event["prev_event_hash"],
                "created_at": event["created_at"],
            }
            if content_digest([payload]) != event["event_hash"]:
                breaks.append({
                    **position,
                    "kind": "event_hash_mismatch",
                    "detail": "事件内容哈希被篡改，与登记摘要不符",
                })
            if event["version_no"] is not None:
                version = self.connection.execute(
                    "SELECT content_sha256 FROM evidence_versions WHERE package_id=? AND version_no=?",
                    (package_id, event["version_no"]),
                ).fetchone()
                if version is None:
                    breaks.append({
                        **position,
                        "kind": "version_missing",
                        "detail": f"事件引用的版本 {event['version_no']} 不存在",
                    })
                elif version["content_sha256"] != event["content_sha256"]:
                    breaks.append({
                        **position,
                        "kind": "digest_mismatch",
                        "detail": f"事件登记摘要与版本 {event['version_no']} 的不可变摘要不一致",
                    })
            allowed, new_status = _transition(event["event_type"], status)
            if not allowed:
                breaks.append({
                    **position,
                    "kind": "state_violation",
                    "detail": f"状态不连续：{event['event_type']} 不能出现在"
                              f"{'链起点' if status is None else status} 之后",
                })
            else:
                status = new_status
                if event["event_type"] in {"register", "handover", "reseal", "retrieve"}:
                    holder = event["to_user_id"]
                    location = event["location_id"]
                if event["event_type"] in {"register", "version_upload", "reseal"}:
                    current_version = event["version_no"]
            prev_hash = event["event_hash"]
            expected_seq += 1
        determinations = self.connection.execute(
            "SELECT * FROM liability_determinations WHERE package_id=? ORDER BY determination_id",
            (package_id,),
        ).fetchall()
        determination_events = {
            event["version_no"] for event in events if event["event_type"] == "determination"
        }
        for determination in determinations:
            version = self.connection.execute(
                "SELECT content_sha256 FROM evidence_versions WHERE package_id=? AND version_no=?",
                (package_id, determination["version_no"]),
            ).fetchone()
            if version is None or version["content_sha256"] != determination["content_sha256"]:
                breaks.append({
                    "seq": None,
                    "event_id": None,
                    "kind": "determination_digest_mismatch",
                    "detail": f"责任认定 {determination['determination_id']} 锁定的版本 "
                              f"{determination['version_no']} 摘要已被改动",
                })
            if determination["version_no"] not in determination_events:
                breaks.append({
                    "seq": None,
                    "event_id": None,
                    "kind": "determination_event_missing",
                    "detail": f"责任认定 {determination['determination_id']} 在保全链上没有对应环节",
                })
        if events:
            diverged = []
            if status != package["custody_status"]:
                diverged.append(f"保管状态：链推导 {status}，台账 {package['custody_status']}")
            if holder != package["current_holder_id"]:
                diverged.append("当前保管人与链推导结果不一致")
            if location != package["current_location_id"]:
                diverged.append("保管位置与链推导结果不一致")
            if current_version != package["current_version_no"]:
                diverged.append("当前版本号与链推导结果不一致")
            if diverged:
                breaks.append({
                    "seq": None,
                    "event_id": None,
                    "kind": "state_divergence",
                    "detail": "；".join(diverged),
                })
        return {
            "package_id": package_id,
            "event_count": len(events),
            "status": "intact" if not breaks else "broken",
            "breaks": breaks,
        }
