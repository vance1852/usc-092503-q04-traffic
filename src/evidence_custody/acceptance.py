"""证据保全链完整流程的离线验收入口。"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .service import EvidenceCustodyService
from .storage import connect, inspect_schema


def run(workspace: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="evidence-custody-") as temporary:
        database = Path(temporary) / "custody.sqlite3"
        connection = connect(database)
        try:
            service = EvidenceCustodyService(connection)
            service.create_user("collector-1", "现场采集员", "collector", "13800001111")
            service.create_user("custodian-1", "证据保管员", "custodian", "13800002222")
            service.create_user("officer-1", "办案民警", "case_officer", "13800003333")
            service.create_user("reviewer-1", "复核人员", "reviewer", "13800004444")
            service.create_user("auditor-1", "审计人员", "auditor", "13800005555")
            service.register_location("custodian-1", "loc-vault", "事故证据库房 A 区", "warehouse")
            service.register_location("custodian-1", "loc-review", "复核调阅室", "cabinet")
            digest_v1 = "a" * 64
            digest_v2 = "b" * 64
            digest_v3 = "c" * 64
            service.register_package(
                "collector-1", "pkg-demo", "case-2026-0901", "路口监控视频与现场照片",
                "loc-vault", digest_v1, "现场采集原始材料",
            )
            service.upload_version("collector-1", "pkg-demo", digest_v2, "补充行车记录仪导出")
            handover = service.initiate_handover(
                "collector-1", "pkg-demo", "custodian-1", "loc-vault", "采集完成入库"
            )
            service.confirm_handover("custodian-1", handover["handover_id"], True, received_digest=digest_v2)
            service.retrieve_package("officer-1", "pkg-demo", "调证字〔2026〕18 号", "责任认定审查")
            returned = service.initiate_handover("officer-1", "pkg-demo", "custodian-1", "loc-vault", "调阅归还")
            service.confirm_handover("custodian-1", returned["handover_id"], True, received_digest=digest_v2)
            determination = service.record_determination("officer-1", "pkg-demo", 2, "甲方承担主要责任")
            service.upload_version("collector-1", "pkg-demo", digest_v3, "申诉阶段补充材料，不覆盖认定版本")
            officer_chain = service.get_chain("officer-1", "pkg-demo")
            auditor_chain = service.get_chain("auditor-1", "pkg-demo")
            verification = service.verify_chain("reviewer-1", "pkg-demo")
            schema = inspect_schema(connection)
        finally:
            connection.close()
    if verification["status"] != "intact":
        raise RuntimeError("保全链校验未通过")
    if schema["missing_tables"] or schema["schema_version"] != "1":
        raise RuntimeError("SQLite 基础结构检查失败")
    officer_contact = officer_chain["package"]["current_holder"]["contact"]
    auditor_contact = auditor_chain["package"]["current_holder"]["contact"]
    if "****" not in auditor_contact or "****" in officer_contact:
        raise RuntimeError("联系方式未按权限遮蔽")
    return {
        "status": "ok",
        "package_id": "pkg-demo",
        "event_count": verification["event_count"],
        "verification": verification["status"],
        "determination_version": determination["version_no"],
        "latest_version": officer_chain["package"]["current_version_no"],
        "officer_contact_visible": officer_contact,
        "auditor_contact_masked": auditor_contact,
        "schema": schema,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="执行证据保全链的离线自检")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    result = run(args.workspace.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
