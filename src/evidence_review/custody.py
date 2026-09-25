"""物证保管链（Chain of Custody）领域用例与校验。

为事故原始材料建立：
- 只追加的内容版本与不可变内容/封装摘要；
- 保管位置与逐次交接的双方确认；
- 拒收、遗失、找回、重新封装、依法调阅的连续状态；
- 哈希链事件，任何状态变化都形成可校验的一环。
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from typing import Any, Mapping

from .clock import SystemClock, isoformat
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction

#: 各角色在保管链中的限定权限。
CUSTODY_PERMISSIONS = {
    "operator": {
        "custody.location.register", "custody.material.register", "custody.version.upload",
        "custody.transfer.propose", "custody.transfer.respond",
        "custody.loss.report", "custody.reseal",
        "custody.access.request", "custody.access.checkout", "custody.access.return",
        "custody.chain.read",
    },
    "statistician": {"custody.chain.read"},
    "approver": {
        "custody.transfer.propose", "custody.transfer.respond", "custody.loss.report",
        "custody.access.request", "custody.access.decide", "custody.material.lock",
        "custody.chain.read",
    },
    "auditor": {"custody.chain.read", "custody.contact.read", "custody.audit.verify"},
}

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

#: 稳定保管状态：只有处于这些状态才能发起交接、报损或重新封装。
STABLE_STATES = frozenset({"sealed", "stored", "resealed", "rejected"})

#: 事件类型到合法状态迁移（None 表示链首；... 表示状态不变）。
LEGAL_TRANSITIONS: Mapping[str, tuple[frozenset[str | None], str | None]] = {
    "material.registered": (frozenset({None}), "sealed"),
    "transfer.proposed": (STABLE_STATES, "in_transfer"),
    "transfer.accepted": (frozenset({"in_transfer"}), "stored"),
    "transfer.rejected": (frozenset({"in_transfer"}), "rejected"),
    "transfer.cancelled": (frozenset({"in_transfer"}), "__payload__"),
    "loss.reported": (STABLE_STATES, "lost"),
    "loss.found": (frozenset({"lost"}), "stored"),
    "material.resealed": (STABLE_STATES, "resealed"),
    "version.added": (STABLE_STATES, "__same__"),
    "access.requested": (STABLE_STATES, "__same__"),
    "access.approved": (STABLE_STATES, "access_pending"),
    "access.rejected": (STABLE_STATES, "__same__"),
    "access.checked_out": (frozenset({"access_pending"}), "accessed"),
    "access.returned": (frozenset({"accessed"}), "stored"),
    "access.expired": (frozenset({"access_pending"}), "stored"),
    "decision.locked": (frozenset({"sealed", "stored", "resealed", "rejected", "in_transfer", "lost", "access_pending", "accessed"}), "__same__"),
}


def event_hash(
    material_id: str,
    sequence_no: int,
    event_type: str,
    actor_id: str,
    state_after: str,
    payload: Mapping[str, Any],
    content_sha256: str | None,
    package_sha256: str | None,
    created_at: str,
    prev_hash: str | None,
) -> str:
    """按规范化信封计算一环的 SHA-256。"""

    envelope = {
        "material_id": material_id,
        "sequence_no": sequence_no,
        "event_type": event_type,
        "actor_id": actor_id,
        "state_after": state_after,
        "content_sha256": content_sha256,
        "package_sha256": package_sha256,
        "payload": payload,
        "prev_hash": prev_hash,
        "created_at": created_at,
    }
    return content_digest([envelope])


def mask_contact(value: str) -> str:
    """按权限不足时的脱敏规则遮蔽联系方式。"""

    if not value:
        return value
    if len(value) <= 2:
        return value[0] + "*"
    if len(value) <= 5:
        return value[0] + "*" * (len(value) - 1)
    return value[0] + "*" * (len(value) - 2) + value[-1]


def _parse_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValidationFailed("时间必须带时区")
    return parsed


class CustodyService:
    """在单个 SQLite 连接上提供物证保管链操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, display_name, role, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in CUSTODY_PERMISSIONS.get(user["role"], frozenset()):
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _audit(self, event_type: str, actor_id: str, payload: Mapping[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            ("custody", str(payload.get("material_id", "")), event_type, actor_id,
             canonical_json(payload), self._now()),
        )

    @staticmethod
    def _hash_value(value: str, field: str) -> str:
        if not isinstance(value, str) or not SHA256_RE.match(value):
            raise ValidationFailed(f"{field} 必须是 64 位小写十六进制 SHA-256")
        return value

    def _material(self, material_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM custody_materials WHERE material_id=?", (material_id,)
        ).fetchone()
        if row is None:
            raise NotFound("物证材料不存在")
        return row

    def _location(self, location_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM custody_locations WHERE location_id=?", (location_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"保管位置不存在: {location_id}")
        return row

    def _append_event(
        self,
        material: sqlite3.Row,
        event_type: str,
        actor_id: str,
        payload: Mapping[str, Any],
        *,
        state_after: str | None = None,
        content_sha256: str | None = None,
        package_sha256: str | None = None,
    ) -> dict[str, Any]:
        """在哈希链尾部追加一环，并同步材料游标。调用方须持有 IMMEDIATE 事务。"""

        material_id = material["material_id"]
        next_seq = material["chain_length"] + 1
        new_state = material["state"] if state_after is None else state_after
        created_at = self._now()
        digest = event_hash(
            material_id, next_seq, event_type, actor_id, new_state, dict(payload),
            content_sha256, package_sha256, created_at, material["last_event_hash"],
        )
        self.connection.execute(
            "INSERT INTO custody_events(material_id,sequence_no,event_type,actor_id,state_after,"
            "payload_json,content_sha256,package_sha256,prev_hash,event_hash,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (material_id, next_seq, event_type, actor_id, new_state, canonical_json(payload),
             content_sha256, package_sha256, material["last_event_hash"], digest, created_at),
        )
        self.connection.execute(
            "UPDATE custody_materials SET state=?, last_event_hash=?, chain_length=? WHERE material_id=?",
            (new_state, digest, next_seq, material_id),
        )
        return {"sequence_no": next_seq, "event_hash": digest, "state_after": new_state}

    def register_location(self, actor_id: str, location_id: str, label: str, kind: str) -> dict[str, Any]:
        self._require(actor_id, "custody.location.register")
        if kind not in {"vault", "room", "vehicle", "court", "external"}:
            raise ValidationFailed("位置类型不受支持")
        if not label.strip():
            raise ValidationFailed("位置名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO custody_locations(location_id,label,kind,created_at) VALUES(?,?,?,?)",
                    (location_id, label.strip(), kind, self._now()),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"保管位置已存在: {location_id}") from exc
        return {"location_id": location_id, "kind": kind}

    def register_material(
        self,
        actor_id: str,
        material_id: str,
        title: str,
        material_type: str,
        location_id: str,
        content_sha256: str,
        package_sha256: str,
        size_bytes: int,
        media_type: str,
        note: str = "",
        batch_id: str | None = None,
        evidence_item_id: int | None = None,
    ) -> dict[str, Any]:
        self._require(actor_id, "custody.material.register")
        self._location(location_id)
        content_sha256 = self._hash_value(content_sha256, "content_sha256")
        package_sha256 = self._hash_value(package_sha256, "package_sha256")
        if content_sha256 == package_sha256:
            raise ValidationFailed("封装摘要不得与内容摘要相同")
        if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes < 0:
            raise ValidationFailed("size_bytes 必须是非负整数")
        if not title.strip() or not material_type.strip() or not media_type.strip():
            raise ValidationFailed("材料名称、类型和媒体类型不能为空")
        if batch_id is not None and self.connection.execute(
            "SELECT 1 FROM batches WHERE batch_id=?", (batch_id,)
        ).fetchone() is None:
            raise NotFound(f"批次不存在: {batch_id}")
        if evidence_item_id is not None and self.connection.execute(
            "SELECT 1 FROM evidence_items WHERE evidence_item_id=?", (evidence_item_id,)
        ).fetchone() is None:
            raise NotFound(f"证据记录不存在: {evidence_item_id}")
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO custody_materials(material_id,title,material_type,batch_id,evidence_item_id,"
                    "state,holder_user_id,location_id,locked_for_decision,registered_by,registered_at,"
                    "last_event_hash,chain_length) VALUES(?,?,?,?,?, 'sealed', ?, ?, 0, ?, ?, NULL, 0)",
                    (material_id, title.strip(), material_type.strip(), batch_id, evidence_item_id,
                     actor_id, location_id, actor_id, now),
                )
                material = self._material(material_id)
                version_cursor = self.connection.execute(
                    "INSERT INTO custody_material_versions(material_id,version_no,content_sha256,package_sha256,"
                    "size_bytes,media_type,change_note,supersedes_version_no,created_by,created_at) "
                    "VALUES(?,1,?,?,?,?,?,NULL,?,?)",
                    (material_id, content_sha256, package_sha256, size_bytes, media_type.strip(),
                     note, actor_id, now),
                )
                payload = {
                    "version_no": 1,
                    "content_sha256": content_sha256,
                    "package_sha256": package_sha256,
                    "size_bytes": size_bytes,
                    "media_type": media_type.strip(),
                    "location_id": location_id,
                    "note": note,
                    "batch_id": batch_id,
                    "evidence_item_id": evidence_item_id,
                }
                event = self._append_event(
                    material, "material.registered", actor_id, payload,
                    state_after="sealed", content_sha256=content_sha256, package_sha256=package_sha256,
                )
                self.connection.execute(
                    "UPDATE custody_materials SET current_version_seq=? WHERE material_id=?",
                    (version_cursor.lastrowid, material_id),
                )
                self._audit("material.registered", actor_id, {"material_id": material_id})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"物证材料编号冲突或关联不存在: {material_id}") from exc
        return {"material_id": material_id, "version_no": 1, "event": event}

    def upload_version(
        self,
        actor_id: str,
        material_id: str,
        content_sha256: str,
        package_sha256: str,
        size_bytes: int,
        change_note: str,
    ) -> dict[str, Any]:
        """上传后续版本：只追加，永不覆盖；已用于责任认定的材料禁止上传。"""

        self._require(actor_id, "custody.version.upload")
        content_sha256 = self._hash_value(content_sha256, "content_sha256")
        package_sha256 = self._hash_value(package_sha256, "package_sha256")
        if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes < 0:
            raise ValidationFailed("size_bytes 必须是非负整数")
        if not change_note.strip():
            raise ValidationFailed("必须填写版本变更说明")
        with transaction(self.connection, immediate=True):
            material = self._material(material_id)
            if material["locked_for_decision"]:
                raise InvalidState("材料已用于责任认定，禁止再上传新版本")
            if material["state"] not in STABLE_STATES:
                raise InvalidState(f"材料当前状态 {material['state']} 不允许上传版本")
            if self.connection.execute(
                "SELECT 1 FROM custody_material_versions WHERE material_id=? AND package_sha256=?",
                (material_id, package_sha256),
            ).fetchone() is not None:
                raise Conflict("该封装摘要已经登记，不能重复上传")
            last = self.connection.execute(
                "SELECT * FROM custody_material_versions WHERE material_id=? "
                "ORDER BY version_no DESC LIMIT 1", (material_id,)
            ).fetchone()
            version_no = last["version_no"] + 1
            now = self._now()
            cursor = self.connection.execute(
                "INSERT INTO custody_material_versions(material_id,version_no,content_sha256,package_sha256,"
                "size_bytes,media_type,change_note,supersedes_version_no,created_by,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (material_id, version_no, content_sha256, package_sha256, size_bytes,
                 last["media_type"], change_note.strip(), last["version_no"], actor_id, now),
            )
            payload = {
                "version_no": version_no,
                "content_sha256": content_sha256,
                "package_sha256": package_sha256,
                "size_bytes": size_bytes,
                "media_type": last["media_type"],
                "change_note": change_note.strip(),
                "supersedes_version_no": last["version_no"],
            }
            event = self._append_event(
                material, "version.added", actor_id, payload,
                content_sha256=content_sha256, package_sha256=package_sha256,
            )
            self.connection.execute(
                "UPDATE custody_materials SET current_version_seq=? WHERE material_id=?",
                (cursor.lastrowid, material_id),
            )
            self._audit("version.added", actor_id, {"material_id": material_id, "version_no": version_no})
        return {"material_id": material_id, "version_no": version_no, "event": event}

    def propose_transfer(
        self,
        actor_id: str,
        material_id: str,
        to_user_id: str,
        to_location_id: str,
        purpose: str,
    ) -> dict[str, Any]:
        self._require(actor_id, "custody.transfer.propose")
        receiver = self._user(to_user_id)
        if "custody.transfer.respond" not in CUSTODY_PERMISSIONS.get(receiver["role"], frozenset()):
            raise Forbidden(f"接收方角色 {receiver['role']} 不在允许接收的限定角色内")
        if to_user_id == actor_id:
            raise ValidationFailed("交接双方不能是同一人")
        self._location(to_location_id)
        if not purpose.strip():
            raise ValidationFailed("交接事由不能为空")
        with transaction(self.connection, immediate=True):
            material = self._material(material_id)
            if material["state"] not in STABLE_STATES:
                raise InvalidState(f"材料当前状态 {material['state']} 不能发起交接")
            if material["holder_user_id"] != actor_id:
                raise Forbidden("只有当前持有人可以发起交接")
            seq_row = self.connection.execute(
                "SELECT COALESCE(MAX(sequence_no),0)+1 AS next FROM custody_transfers WHERE material_id=?",
                (material_id,),
            ).fetchone()
            now = self._now()
            cursor = self.connection.execute(
                "INSERT INTO custody_transfers(material_id,sequence_no,from_user_id,to_user_id,"
                "from_location_id,to_location_id,state,purpose,proposed_at,proposed_by) "
                "VALUES(?,?,?,?,?,?, 'proposed', ?,?,?)",
                (material_id, seq_row["next"], actor_id, to_user_id, material["location_id"],
                 to_location_id, purpose.strip(), now, actor_id),
            )
            transfer_id = cursor.lastrowid
            payload = {
                "transfer_id": transfer_id,
                "sequence_no": seq_row["next"],
                "from_user_id": actor_id,
                "to_user_id": to_user_id,
                "from_location_id": material["location_id"],
                "to_location_id": to_location_id,
                "purpose": purpose.strip(),
                "prior_state": material["state"],
            }
            event = self._append_event(
                material, "transfer.proposed", actor_id, payload, state_after="in_transfer"
            )
            self.connection.execute(
                "UPDATE custody_materials SET location_id=? WHERE material_id=?",
                (to_location_id, material_id),
            )
            self._audit("transfer.proposed", actor_id, {"material_id": material_id, "transfer_id": transfer_id})
        return {"transfer_id": transfer_id, "state": "proposed", "event": event}

    def respond_transfer(self, actor_id: str, transfer_id: int, accept: bool, note: str = "") -> dict[str, Any]:
        self._require(actor_id, "custody.transfer.respond")
        with transaction(self.connection, immediate=True):
            transfer = self.connection.execute(
                "SELECT * FROM custody_transfers WHERE transfer_id=?", (transfer_id,)
            ).fetchone()
            if transfer is None:
                raise NotFound("交接记录不存在")
            if transfer["state"] != "proposed":
                raise InvalidState("交接已经处理或撤销")
            if transfer["to_user_id"] != actor_id:
                raise Forbidden("只有指定接收方可以确认或拒收")
            material = self._material(transfer["material_id"])
            if material["state"] != "in_transfer":
                raise InvalidState("材料不处于交接中，无法确认")
            now = self._now()
            if accept:
                self.connection.execute(
                    "UPDATE custody_transfers SET state='accepted',responded_at=?,reject_reason=? "
                    "WHERE transfer_id=?",
                    (now, note.strip() or None, transfer_id),
                )
                payload = {
                    "transfer_id": transfer_id,
                    "from_user_id": transfer["from_user_id"],
                    "to_user_id": actor_id,
                    "to_location_id": transfer["to_location_id"],
                    "note": note.strip(),
                }
                event = self._append_event(
                    material, "transfer.accepted", actor_id, payload, state_after="stored"
                )
                self.connection.execute(
                    "UPDATE custody_materials SET holder_user_id=?,location_id=? WHERE material_id=?",
                    (actor_id, transfer["to_location_id"], transfer["material_id"]),
                )
            else:
                if not note.strip():
                    raise ValidationFailed("拒收必须填写原因")
                self.connection.execute(
                    "UPDATE custody_transfers SET state='rejected',responded_at=?,reject_reason=? "
                    "WHERE transfer_id=?",
                    (now, note.strip(), transfer_id),
                )
                payload = {
                    "transfer_id": transfer_id,
                    "from_user_id": transfer["from_user_id"],
                    "to_user_id": actor_id,
                    "return_location_id": transfer["from_location_id"],
                    "reject_reason": note.strip(),
                }
                event = self._append_event(
                    material, "transfer.rejected", actor_id, payload, state_after="rejected"
                )
                self.connection.execute(
                    "UPDATE custody_materials SET holder_user_id=?,location_id=? WHERE material_id=?",
                    (transfer["from_user_id"], transfer["from_location_id"], transfer["material_id"]),
                )
            self._audit(
                "transfer.accepted" if accept else "transfer.rejected",
                actor_id, {"material_id": transfer["material_id"], "transfer_id": transfer_id},
            )
        return {"transfer_id": transfer_id, "state": "accepted" if accept else "rejected", "event": event}

    def cancel_transfer(self, actor_id: str, transfer_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "custody.transfer.propose")
        with transaction(self.connection, immediate=True):
            transfer = self.connection.execute(
                "SELECT * FROM custody_transfers WHERE transfer_id=?", (transfer_id,)
            ).fetchone()
            if transfer is None:
                raise NotFound("交接记录不存在")
            if transfer["state"] != "proposed":
                raise InvalidState("交接已经处理，不能撤销")
            if transfer["proposed_by"] != actor_id:
                raise Forbidden("只有交出方可以撤销交接")
            material = self._material(transfer["material_id"])
            if material["state"] != "in_transfer":
                raise InvalidState("材料不处于交接中")
            if not reason.strip():
                raise ValidationFailed("撤销原因不能为空")
            self.connection.execute(
                "UPDATE custody_transfers SET state='cancelled',responded_at=?,reject_reason=? "
                "WHERE transfer_id=?",
                (self._now(), reason.strip(), transfer_id),
            )
            payload = {
                "transfer_id": transfer_id,
                "prior_state": "stored" if material["chain_length"] > 1 else material["state"],
                "reason": reason.strip(),
            }
            # 撤销后回到发起交接之前的稳定状态：按该材料最近一次稳定状态回放。
            prior_event = self.connection.execute(
                "SELECT state_after FROM custody_events WHERE material_id=? AND event_type IN "
                "('material.registered','transfer.accepted','transfer.rejected','loss.found',"
                "'material.resealed','access.returned') ORDER BY sequence_no DESC LIMIT 1",
                (transfer["material_id"],),
            ).fetchone()
            prior_state = prior_event["state_after"] if prior_event is not None else "sealed"
            payload["prior_state"] = prior_state
            event = self._append_event(
                material, "transfer.cancelled", actor_id, payload, state_after=prior_state
            )
            self.connection.execute(
                "UPDATE custody_materials SET location_id=? WHERE material_id=?",
                (transfer["from_location_id"], transfer["material_id"]),
            )
            self._audit("transfer.cancelled", actor_id,
                        {"material_id": transfer["material_id"], "transfer_id": transfer_id})
        return {"transfer_id": transfer_id, "state": "cancelled", "event": event}

    def report_loss(self, actor_id: str, material_id: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "custody.loss.report")
        if not reason.strip():
            raise ValidationFailed("遗失情况说明不能为空")
        with transaction(self.connection, immediate=True):
            material = self._material(material_id)
            if material["state"] not in STABLE_STATES:
                raise InvalidState(f"材料当前状态 {material['state']} 不能登记遗失")
            if material["holder_user_id"] != actor_id and self._user(actor_id)["role"] != "approver":
                raise Forbidden("只有当前持有人或审批角色可以登记遗失")
            last_holder = material["holder_user_id"]
            payload = {"last_holder_user_id": last_holder, "reason": reason.strip()}
            event = self._append_event(
                material, "loss.reported", actor_id, payload, state_after="lost"
            )
            self.connection.execute(
                "UPDATE custody_materials SET holder_user_id=NULL WHERE material_id=?", (material_id,)
            )
            self._audit("loss.reported", actor_id, {"material_id": material_id})
        return {"material_id": material_id, "state": "lost", "event": event}

    def report_found(self, actor_id: str, material_id: str, location_id: str, note: str) -> dict[str, Any]:
        self._require(actor_id, "custody.loss.report")
        self._location(location_id)
        if not note.strip():
            raise ValidationFailed("找回情况说明不能为空")
        with transaction(self.connection, immediate=True):
            material = self._material(material_id)
            if material["state"] != "lost":
                raise InvalidState("材料未处于遗失状态")
            self.connection.execute(
                "UPDATE custody_materials SET holder_user_id=?,location_id=? WHERE material_id=?",
                (actor_id, location_id, material_id),
            )
            payload = {"location_id": location_id, "holder_user_id": actor_id, "note": note.strip()}
            event = self._append_event(
                material, "loss.found", actor_id, payload, state_after="stored"
            )
            self._audit("loss.found", actor_id, {"material_id": material_id})
        return {"material_id": material_id, "state": "stored", "event": event}

    def reseal(
        self,
        actor_id: str,
        material_id: str,
        new_package_sha256: str,
        witness_user_id: str,
        note: str,
    ) -> dict[str, Any]:
        """重新封装：内容摘要不变，封装摘要更新，须有见证人共同记录。"""

        self._require(actor_id, "custody.reseal")
        new_package_sha256 = self._hash_value(new_package_sha256, "new_package_sha256")
        witness = self._user(witness_user_id)
        if witness_user_id == actor_id:
            raise ValidationFailed("见证人不能是操作人本人")
        if witness["role"] not in {"approver", "auditor"}:
            raise Forbidden("见证人须为审批或审计角色")
        if not note.strip():
            raise ValidationFailed("重新封装说明不能为空")
        with transaction(self.connection, immediate=True):
            material = self._material(material_id)
            if material["locked_for_decision"]:
                raise InvalidState("材料已用于责任认定，禁止重新封装")
            if material["state"] not in STABLE_STATES:
                raise InvalidState(f"材料当前状态 {material['state']} 不能重新封装")
            current = self.connection.execute(
                "SELECT * FROM custody_material_versions WHERE version_seq=?",
                (material["current_version_seq"],),
            ).fetchone()
            if new_package_sha256 == current["package_sha256"]:
                raise Conflict("新封装摘要与当前封装一致，无需重新封装")
            if self.connection.execute(
                "SELECT 1 FROM custody_material_versions WHERE material_id=? AND package_sha256=?",
                (material_id, new_package_sha256),
            ).fetchone() is not None:
                raise Conflict("该封装摘要已经登记")
            version_no = current["version_no"] + 1
            now = self._now()
            cursor = self.connection.execute(
                "INSERT INTO custody_material_versions(material_id,version_no,content_sha256,package_sha256,"
                "size_bytes,media_type,change_note,supersedes_version_no,created_by,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (material_id, version_no, current["content_sha256"], new_package_sha256,
                 current["size_bytes"], current["media_type"], note.strip(), current["version_no"],
                 actor_id, now),
            )
            payload = {
                "version_no": version_no,
                "content_sha256": current["content_sha256"],
                "package_sha256": new_package_sha256,
                "supersedes_package_sha256": current["package_sha256"],
                "witness_user_id": witness_user_id,
                "note": note.strip(),
            }
            event = self._append_event(
                material, "material.resealed", actor_id, payload,
                content_sha256=current["content_sha256"], package_sha256=new_package_sha256,
                state_after="resealed",
            )
            self.connection.execute(
                "UPDATE custody_materials SET current_version_seq=? WHERE material_id=?",
                (cursor.lastrowid, material_id),
            )
            self._audit("material.resealed", actor_id,
                        {"material_id": material_id, "version_no": version_no})
        return {"material_id": material_id, "version_no": version_no, "event": event}

    def request_access(
        self,
        actor_id: str,
        material_id: str,
        requester_name: str,
        requester_contact: str,
        legal_basis: str,
        purpose: str,
    ) -> dict[str, Any]:
        self._require(actor_id, "custody.access.request")
        for field_name, value in (
            ("requester_name", requester_name), ("requester_contact", requester_contact),
            ("legal_basis", legal_basis), ("purpose", purpose),
        ):
            if not value.strip():
                raise ValidationFailed(f"{field_name} 不能为空")
        with transaction(self.connection, immediate=True):
            material = self._material(material_id)
            if material["state"] not in STABLE_STATES:
                raise InvalidState(f"材料当前状态 {material['state']} 不受理调阅申请")
            now = self._now()
            cursor = self.connection.execute(
                "INSERT INTO custody_access_requests(material_id,requester_user_id,requester_name,"
                "requester_contact,legal_basis,purpose,state,created_at) "
                "VALUES(?,?,?,?,?,?, 'pending',?)",
                (material_id, actor_id, requester_name.strip(), requester_contact.strip(),
                 legal_basis.strip(), purpose.strip(), now),
            )
            request_id = cursor.lastrowid
            payload = {
                "request_id": request_id,
                "requester_name": requester_name.strip(),
                "requester_contact": requester_contact.strip(),
                "legal_basis": legal_basis.strip(),
                "purpose": purpose.strip(),
                "registered_by": actor_id,
            }
            event = self._append_event(material, "access.requested", actor_id, payload)
            self._audit("access.requested", actor_id,
                        {"material_id": material_id, "request_id": request_id})
        return {"request_id": request_id, "state": "pending", "event": event}

    def decide_access(
        self, actor_id: str, request_id: int, approve: bool, note: str, approved_until: str | None = None
    ) -> dict[str, Any]:
        self._require(actor_id, "custody.access.decide")
        if not note.strip():
            raise ValidationFailed("审批意见不能为空")
        with transaction(self.connection, immediate=True):
            request = self.connection.execute(
                "SELECT * FROM custody_access_requests WHERE request_id=?", (request_id,)
            ).fetchone()
            if request is None:
                raise NotFound("调阅申请不存在")
            if request["state"] != "pending":
                raise InvalidState("调阅申请已经处理")
            material = self._material(request["material_id"])
            if material["state"] not in STABLE_STATES:
                raise InvalidState("材料不在稳定保管状态，存在未完结的在先调阅或交接")
            now = self._now()
            payload_base = {
                "request_id": request_id,
                "requester_name": request["requester_name"],
                "note": note.strip(),
            }
            if approve:
                if not approved_until or not approved_until.strip():
                    raise ValidationFailed("批准调阅必须填写批准截止时间")
                try:
                    deadline = _parse_iso(approved_until.strip())
                except ValueError as exc:
                    raise ValidationFailed("批准截止时间必须是带时区的 ISO-8601 时间") from exc
                if deadline <= self.clock.now():
                    raise ValidationFailed("批准截止时间必须晚于当前时间")
                self.connection.execute(
                    "UPDATE custody_access_requests SET state='approved',decided_by=?,decided_at=?,"
                    "decision_note=?,approved_until=? WHERE request_id=?",
                    (actor_id, now, note.strip(), approved_until.strip(), request_id),
                )
                payload = {**payload_base, "approved_until": approved_until.strip()}
                event = self._append_event(
                    material, "access.approved", actor_id, payload, state_after="access_pending"
                )
            else:
                self.connection.execute(
                    "UPDATE custody_access_requests SET state='rejected',decided_by=?,decided_at=?,"
                    "decision_note=? WHERE request_id=?",
                    (actor_id, now, note.strip(), request_id),
                )
                event = self._append_event(
                    material, "access.rejected", actor_id, payload_base
                )
            self._audit("access.approved" if approve else "access.rejected", actor_id,
                        {"material_id": request["material_id"], "request_id": request_id})
        return {"request_id": request_id, "state": "approved" if approve else "rejected", "event": event}

    def checkout_access(self, actor_id: str, request_id: int, handover_note: str) -> dict[str, Any]:
        self._require(actor_id, "custody.access.checkout")
        if not handover_note.strip():
            raise ValidationFailed("交付说明不能为空")
        with transaction(self.connection, immediate=True):
            request = self.connection.execute(
                "SELECT * FROM custody_access_requests WHERE request_id=?", (request_id,)
            ).fetchone()
            if request is None:
                raise NotFound("调阅申请不存在")
            if request["state"] != "approved":
                raise InvalidState("调阅申请未获批准或已经交付")
            material = self._material(request["material_id"])
            if material["state"] != "access_pending":
                raise InvalidState("材料不处于待调阅交付状态")
            if self.clock.now() >= _parse_iso(request["approved_until"]):
                raise InvalidState("批准调阅期限已届满，应先办理延期或归还")
            payload = {
                "request_id": request_id,
                "requester_name": request["requester_name"],
                "approved_until": request["approved_until"],
                "handover_note": handover_note.strip(),
            }
            event = self._append_event(
                material, "access.checked_out", actor_id, payload, state_after="accessed"
            )
            self._audit("access.checked_out", actor_id,
                        {"material_id": request["material_id"], "request_id": request_id})
        return {"request_id": request_id, "state": "checked_out", "event": event}

    def return_access(self, actor_id: str, request_id: int, location_id: str, note: str) -> dict[str, Any]:
        self._require(actor_id, "custody.access.return")
        self._location(location_id)
        if not note.strip():
            raise ValidationFailed("归还说明不能为空")
        with transaction(self.connection, immediate=True):
            request = self.connection.execute(
                "SELECT * FROM custody_access_requests WHERE request_id=?", (request_id,)
            ).fetchone()
            if request is None:
                raise NotFound("调阅申请不存在")
            if request["state"] != "approved" or request["returned_at"] is not None:
                raise InvalidState("调阅记录不在待归还状态")
            material = self._material(request["material_id"])
            if material["state"] != "accessed":
                raise InvalidState("材料未处于调阅出库状态")
            now = self._now()
            self.connection.execute(
                "UPDATE custody_access_requests SET state='returned',returned_at=?,return_note=? "
                "WHERE request_id=?",
                (now, note.strip(), request_id),
            )
            self.connection.execute(
                "UPDATE custody_materials SET holder_user_id=?,location_id=? WHERE material_id=?",
                (actor_id, location_id, request["material_id"]),
            )
            payload = {
                "request_id": request_id,
                "location_id": location_id,
                "holder_user_id": actor_id,
                "note": note.strip(),
            }
            event = self._append_event(
                material, "access.returned", actor_id, payload, state_after="stored"
            )
            self._audit("access.returned", actor_id,
                        {"material_id": request["material_id"], "request_id": request_id})
        return {"request_id": request_id, "state": "returned", "event": event}

    def expire_access(self, actor_id: str, request_id: int, note: str) -> dict[str, Any]:
        """批准期限届满未出库：调阅申请失效，材料回到稳定保管状态。"""

        self._require(actor_id, "custody.access.decide")
        if not note.strip():
            raise ValidationFailed("失效说明不能为空")
        with transaction(self.connection, immediate=True):
            request = self.connection.execute(
                "SELECT * FROM custody_access_requests WHERE request_id=?", (request_id,)
            ).fetchone()
            if request is None:
                raise NotFound("调阅申请不存在")
            if request["state"] != "approved":
                raise InvalidState("只有已批准待交付的调阅可以标记到期失效")
            material = self._material(request["material_id"])
            if material["state"] != "access_pending":
                raise InvalidState("材料不处于待调阅交付状态")
            self.connection.execute(
                "UPDATE custody_access_requests SET state='expired',decision_note=? WHERE request_id=?",
                (note.strip(), request_id),
            )
            payload = {
                "request_id": request_id,
                "requester_name": request["requester_name"],
                "approved_until": request["approved_until"],
                "note": note.strip(),
            }
            event = self._append_event(
                material, "access.expired", actor_id, payload, state_after="stored"
            )
            self._audit("access.expired", actor_id,
                        {"material_id": request["material_id"], "request_id": request_id})
        return {"request_id": request_id, "state": "expired", "event": event}

    def lock_for_decision(
        self, actor_id: str, material_id: str, decision_reference: str, version_no: int | None = None
    ) -> dict[str, Any]:
        """材料用于责任认定后锁定：已锁定的版本不得被后续上传覆盖。"""

        self._require(actor_id, "custody.material.lock")
        if not decision_reference.strip():
            raise ValidationFailed("责任认定文书编号不能为空")
        with transaction(self.connection, immediate=True):
            material = self._material(material_id)
            if material["locked_for_decision"]:
                raise InvalidState("材料已经锁定于责任认定版本")
            current = self.connection.execute(
                "SELECT * FROM custody_material_versions WHERE version_seq=?",
                (material["current_version_seq"],),
            ).fetchone()
            if version_no is not None and version_no != current["version_no"]:
                raise InvalidState(
                    f"指定锁定第 {version_no} 版，但当前为第 {current['version_no']} 版"
                )
            payload = {
                "decision_reference": decision_reference.strip(),
                "version_no": current["version_no"],
                "content_sha256": current["content_sha256"],
                "package_sha256": current["package_sha256"],
            }
            event = self._append_event(material, "decision.locked", actor_id, payload)
            self.connection.execute(
                "UPDATE custody_materials SET locked_for_decision=1 WHERE material_id=?", (material_id,)
            )
            self._audit("decision.locked", actor_id,
                        {"material_id": material_id, "decision_reference": decision_reference.strip()})
        return {
            "material_id": material_id,
            "locked_version_no": current["version_no"],
            "decision_reference": decision_reference.strip(),
            "event": event,
        }

    def lock_batch_within_transaction(
        self, actor_id: str, batch_id: str, decision_reference: str
    ) -> list[dict[str, Any]]:
        """责任认定落定后，锁定批次及其证据记录关联的全部材料。

        调用方必须已持有 IMMEDIATE 事务，保证决定与锁定原子提交。
        """

        rows = self.connection.execute(
            "SELECT material_id FROM custody_materials WHERE locked_for_decision=0 AND ("
            "batch_id=? OR evidence_item_id IN ("
            "SELECT evidence_item_id FROM evidence_items WHERE batch_id=?))",
            (batch_id, batch_id),
        ).fetchall()
        locked: list[dict[str, Any]] = []
        for row in rows:
            material = self._material(row["material_id"])
            current = self.connection.execute(
                "SELECT * FROM custody_material_versions WHERE version_seq=?",
                (material["current_version_seq"],),
            ).fetchone()
            payload = {
                "decision_reference": decision_reference.strip(),
                "batch_id": batch_id,
                "version_no": current["version_no"],
                "content_sha256": current["content_sha256"],
                "package_sha256": current["package_sha256"],
            }
            event = self._append_event(material, "decision.locked", actor_id, payload)
            self.connection.execute(
                "UPDATE custody_materials SET locked_for_decision=1 WHERE material_id=?",
                (row["material_id"],),
            )
            locked.append({
                "material_id": row["material_id"],
                "locked_version_no": current["version_no"],
                "event_sequence_no": event["sequence_no"],
            })
        return locked

    def verification(self, actor_id: str, material_id: str) -> dict[str, Any]:
        """审计专用：仅返回哈希链与状态机重放结论。"""

        self._require(actor_id, "custody.audit.verify")
        self._material(material_id)
        return verify_chain(self.connection, material_id)

    def list_materials(self, actor_id: str, batch_id: str | None = None) -> dict[str, Any]:
        self._require(actor_id, "custody.chain.read")
        sql = (
            "SELECT material_id,title,material_type,batch_id,evidence_item_id,state,"
            "current_version_seq,holder_user_id,location_id,locked_for_decision,chain_length "
            "FROM custody_materials"
        )
        if batch_id is not None:
            rows = self.connection.execute(sql + " WHERE batch_id=? ORDER BY material_id", (batch_id,)).fetchall()
        else:
            rows = self.connection.execute(sql + " ORDER BY material_id").fetchall()
        return {"materials": [dict(row) for row in rows]}

    def chain_view(self, actor_id: str, material_id: str) -> dict[str, Any]:
        """向办案/审计人员展示完整保全链，并按权限遮蔽联系方式。"""

        user = self._require(actor_id, "custody.chain.read")
        can_see_contacts = "custody.contact.read" in CUSTODY_PERMISSIONS.get(user["role"], frozenset())
        material = self._material(material_id)
        versions = [
            dict(row) for row in self.connection.execute(
                "SELECT version_seq,version_no,content_sha256,package_sha256,size_bytes,media_type,"
                "change_note,supersedes_version_no,created_by,created_at FROM custody_material_versions "
                "WHERE material_id=? ORDER BY version_no", (material_id,)
            ).fetchall()
        ]
        transfers = [
            dict(row) for row in self.connection.execute(
                "SELECT transfer_id,sequence_no,from_user_id,to_user_id,from_location_id,to_location_id,"
                "state,purpose,proposed_at,proposed_by,responded_at,reject_reason FROM custody_transfers "
                "WHERE material_id=? ORDER BY transfer_id", (material_id,)
            ).fetchall()
        ]
        access_rows = self.connection.execute(
            "SELECT * FROM custody_access_requests WHERE material_id=? ORDER BY request_id", (material_id,)
        ).fetchall()
        access_requests: list[dict[str, Any]] = []
        for row in access_rows:
            item = dict(row)
            if not can_see_contacts:
                item["requester_contact"] = mask_contact(item["requester_contact"])
                item["contact_masked"] = True
            else:
                item["contact_masked"] = False
            access_requests.append(item)
        events = [
            dict(row) | {"payload": json.loads(row["payload_json"])}
            for row in self.connection.execute(
                "SELECT event_id,sequence_no,event_type,actor_id,state_after,payload_json,"
                "content_sha256,package_sha256,prev_hash,event_hash,created_at FROM custody_events "
                "WHERE material_id=? ORDER BY sequence_no", (material_id,)
            ).fetchall()
        ]
        if not can_see_contacts:
            for event in events:
                payload = event["payload"]
                if isinstance(payload, dict) and "requester_contact" in payload:
                    payload["requester_contact"] = mask_contact(payload["requester_contact"])
                    payload["contact_masked"] = True
        verification = verify_chain(self.connection, material_id)
        return {
            "material": dict(material),
            "versions": versions,
            "transfers": transfers,
            "access_requests": access_requests,
            "events": events,
            "verification": verification,
            "contact_visible": can_see_contacts,
        }


def verify_chain(connection: sqlite3.Connection, material_id: str) -> dict[str, Any]:
    """重放哈希链与状态机，指出链条断裂或摘要不一致的具体位置。"""

    material = connection.execute(
        "SELECT * FROM custody_materials WHERE material_id=?", (material_id,)
    ).fetchone()
    if material is None:
        raise NotFound("物证材料不存在")
    anomalies: list[dict[str, Any]] = []

    def flag(code: str, message: str, *, sequence_no: int | None = None, event_id: int | None = None,
             **extra: Any) -> None:
        anomaly = {"code": code, "message": message}
        if sequence_no is not None:
            anomaly["sequence_no"] = sequence_no
        if event_id is not None:
            anomaly["event_id"] = event_id
        anomaly.update(extra)
        anomalies.append(anomaly)

    events = connection.execute(
        "SELECT * FROM custody_events WHERE material_id=? ORDER BY sequence_no", (material_id,)
    ).fetchall()

    # 1) 序号连续性与链首。
    if not events:
        flag("chain_empty", "保管链没有任何事件")
    expected_state: str | None = None
    expected_holder: str | None = None
    prev_hash: str | None = None
    current_version_no = 0
    locked_at_version: int | None = None
    open_transfer_ids: set[int] = set()
    pending_access: int | None = None
    checked_out_access: int | None = None

    for index, event in enumerate(events, start=1):
        if event["sequence_no"] != index:
            flag("chain_broken", f"事件序号断裂：应为 {index}，实际为 {event['sequence_no']}",
                 sequence_no=event["sequence_no"], event_id=event["event_id"])
        if event["prev_hash"] != prev_hash:
            flag("chain_broken",
                 f"前向哈希不衔接：期望 {prev_hash}，记录 {event['prev_hash']}",
                 sequence_no=event["sequence_no"], event_id=event["event_id"])
        payload = json.loads(event["payload_json"])
        recomputed = event_hash(
            material_id, event["sequence_no"], event["event_type"], event["actor_id"],
            event["state_after"], payload, event["content_sha256"], event["package_sha256"],
            event["created_at"], event["prev_hash"],
        )
        if recomputed != event["event_hash"]:
            flag("hash_mismatch",
                 f"事件内容与哈希不一致：重算 {recomputed}，记录 {event['event_hash']}",
                 sequence_no=event["sequence_no"], event_id=event["event_id"],
                 recomputed=recomputed, stored=event["event_hash"])

        # 2) 状态机重放。
        rule = LEGAL_TRANSITIONS.get(event["event_type"])
        if rule is None:
            flag("unknown_event", f"未知事件类型 {event['event_type']}",
                 sequence_no=event["sequence_no"], event_id=event["event_id"])
            target_state: str | None = None
        else:
            allowed, target = rule
            if target == "__same__":
                target = expected_state
            elif target == "__payload__":
                target = payload.get("prior_state")
            if expected_state not in allowed:
                flag("illegal_transition",
                     f"非法状态迁移：{event['event_type']} 不能从 {expected_state} 发起",
                     sequence_no=event["sequence_no"], event_id=event["event_id"])
            elif target is not None and event["state_after"] != target:
                flag("state_mismatch",
                     f"事件后状态应为 {target}，实际记录 {event['state_after']}",
                     sequence_no=event["sequence_no"], event_id=event["event_id"])
            target_state = target

        # 3) 版本摘要与版本表逐环核对。
        if event["event_type"] in {"material.registered", "version.added", "material.resealed"}:
            version_no = payload.get("version_no")
            version_row = connection.execute(
                "SELECT * FROM custody_material_versions WHERE material_id=? AND version_no=?",
                (material_id, version_no),
            ).fetchone()
            if version_row is None:
                flag("digest_mismatch", f"事件引用的版本 {version_no} 在版本表中不存在",
                     sequence_no=event["sequence_no"])
            else:
                if payload.get("content_sha256") != version_row["content_sha256"]:
                    flag("digest_mismatch",
                         f"第 {version_no} 版事件内容摘要与版本表不一致",
                         sequence_no=event["sequence_no"], version_no=version_no,
                         event_digest=payload.get("content_sha256"),
                         stored_digest=version_row["content_sha256"])
                if payload.get("package_sha256") != version_row["package_sha256"]:
                    flag("digest_mismatch",
                         f"第 {version_no} 版事件封装摘要与版本表不一致",
                         sequence_no=event["sequence_no"], version_no=version_no,
                         event_digest=payload.get("package_sha256"),
                         stored_digest=version_row["package_sha256"])
                if event["content_sha256"] is not None and event["content_sha256"] != version_row["content_sha256"]:
                    flag("digest_mismatch",
                         f"事件列 content_sha256 与第 {version_no} 版内容摘要不一致",
                         sequence_no=event["sequence_no"], version_no=version_no)
            if locked_at_version is not None and event["event_type"] == "version.added":
                flag("post_lock_upload",
                     f"责任认定锁定第 {locked_at_version} 版后又上传第 {version_no} 版",
                     sequence_no=event["sequence_no"], version_no=version_no)
            current_version_no = version_no or current_version_no

        # 4) 交接与调阅的配对状态。
        if event["event_type"] == "transfer.proposed":
            open_transfer_ids.add(payload.get("transfer_id"))
        if event["event_type"] in {"transfer.accepted", "transfer.rejected", "transfer.cancelled"}:
            open_transfer_ids.discard(payload.get("transfer_id"))
            transfer_row = connection.execute(
                "SELECT state FROM custody_transfers WHERE transfer_id=?",
                (payload.get("transfer_id"),),
            ).fetchone()
            expected_transfer_state = {
                "transfer.accepted": "accepted",
                "transfer.rejected": "rejected",
                "transfer.cancelled": "cancelled",
            }[event["event_type"]]
            if transfer_row is None:
                flag("transfer_missing", "交接记录在交接表中不存在",
                     sequence_no=event["sequence_no"], transfer_id=payload.get("transfer_id"))
            elif transfer_row["state"] != expected_transfer_state:
                flag("transfer_state_mismatch",
                     f"交接表状态 {transfer_row['state']} 与事件 {expected_transfer_state} 不一致",
                     sequence_no=event["sequence_no"], transfer_id=payload.get("transfer_id"))
        if event["event_type"] == "access.requested":
            request_row = connection.execute(
                "SELECT state FROM custody_access_requests WHERE request_id=?",
                (payload.get("request_id"),),
            ).fetchone()
            if request_row is None:
                flag("access_request_missing", "调阅申请在申请表中不存在",
                     sequence_no=event["sequence_no"], request_id=payload.get("request_id"))
        if event["event_type"] == "access.approved":
            pending_access = payload.get("request_id")
        if event["event_type"] == "access.checked_out":
            checked_out_access = pending_access
            pending_access = None
        if event["event_type"] in {"access.returned", "access.rejected", "access.expired"}:
            pending_access = None
            checked_out_access = None
        if event["event_type"] == "decision.locked":
            locked_at_version = payload.get("version_no")

        # 5) 持有人重放。
        if event["event_type"] == "material.registered":
            expected_holder = event["actor_id"]
        elif event["event_type"] == "transfer.accepted":
            expected_holder = event["actor_id"]
        elif event["event_type"] == "loss.reported":
            expected_holder = None
        elif event["event_type"] == "loss.found":
            expected_holder = event["actor_id"]
        elif event["event_type"] == "access.returned":
            expected_holder = event["actor_id"]

        if target_state is not None:
            expected_state = target_state
        prev_hash = event["event_hash"]

    # 6) 材料主档与链末态的漂移。
    if events:
        last_event = events[-1]
        if material["state"] != last_event["state_after"]:
            flag("state_drift",
                 f"材料主档状态 {material['state']} 与链末态 {last_event['state_after']} 不一致",
                 sequence_no=last_event["sequence_no"])
        if material["last_event_hash"] != last_event["event_hash"]:
            flag("chain_tip_mismatch",
                 "材料主档链尾哈希与最后一环不一致，存在尾部截断或篡改",
                 sequence_no=last_event["sequence_no"])
        if material["chain_length"] != len(events):
            flag("chain_length_mismatch",
                 f"材料主档记录链长 {material['chain_length']}，实际事件 {len(events)}")
        if material["holder_user_id"] != expected_holder:
            flag("holder_drift",
                 f"主档持有人 {material['holder_user_id']} 与链条重放持有人 {expected_holder} 不一致",
                 sequence_no=last_event["sequence_no"])

    # 7) 当前版本指针核对。
    current_version_row = connection.execute(
        "SELECT v.version_no,v.content_sha256,v.package_sha256 FROM custody_material_versions v "
        "WHERE v.version_seq=?", (material["current_version_seq"],),
    ).fetchone() if material["current_version_seq"] is not None else None
    if current_version_row is None:
        flag("current_version_missing", "材料缺少当前版本指针")
    else:
        if current_version_row["version_no"] != current_version_no:
            flag("digest_mismatch",
                 f"当前版本指针指向第 {current_version_row['version_no']} 版，"
                 f"链条最后登记为第 {current_version_no} 版")
        last_digest_event = None
        for event in reversed(events):
            if event["event_type"] in {"material.registered", "version.added", "material.resealed"}:
                last_digest_event = event
                break
        if last_digest_event is not None:
            payload = json.loads(last_digest_event["payload_json"])
            if payload.get("content_sha256") != current_version_row["content_sha256"]:
                flag("digest_mismatch", "当前版本内容摘要与最后版本事件不一致",
                     sequence_no=last_digest_event["sequence_no"])
            if payload.get("package_sha256") != current_version_row["package_sha256"]:
                flag("digest_mismatch", "当前版本封装摘要与最后版本事件不一致",
                     sequence_no=last_digest_event["sequence_no"])

    # 8) 悬挂的交接/调阅状态。
    if material["state"] == "in_transfer" and not open_transfer_ids:
        flag("orphan_transfer", "材料处于交接中，但链条中没有待确认的交接")
    if open_transfer_ids and material["state"] != "in_transfer":
        flag("orphan_transfer",
            f"交接 {sorted(open_transfer_ids)} 仍待确认，但材料状态为 {material['state']}",
            transfer_ids=sorted(open_transfer_ids))
    if material["state"] == "access_pending" and pending_access is None:
        flag("orphan_access", "材料处于待调阅交付，但链条中没有已批准待交付的调阅")
    if material["state"] == "accessed" and checked_out_access is None:
        flag("orphan_access", "材料处于调阅出库状态，但链条中没有对应的出库记录")
    if material["locked_for_decision"] and locked_at_version is None:
        flag("lock_without_event", "材料标记为责任认定锁定，但链条中没有锁定事件")

    return {
        "material_id": material_id,
        "intact": not anomalies,
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
    }
