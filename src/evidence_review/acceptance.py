"""完整产品流程的离线验收入口。"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .custody import CustodyService
from .errors import InvalidState
from .jsonio import load_json
from .service import EvidenceReviewService
from .storage import connect, inspect_schema


def run(workspace: Path) -> dict[str, object]:
    fixtures = workspace / "fixtures"
    evidence_protocol = load_json(fixtures / "demo_evidence_protocol.json")
    evidence_item_rows = [
        json.loads(line)
        for line in (fixtures / "demo_evidence_items.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    with tempfile.TemporaryDirectory(prefix="device-reviews-") as temporary:
        database = Path(temporary) / "foundation.sqlite3"
        connection = connect(database)
        try:
            service = EvidenceReviewService(connection)
            service.create_user("operator-1", "测试操作员", "operator")
            service.create_user("operator-2", "物证接收员", "operator")
            service.create_user("stat-1", "统计负责人", "statistician")
            service.create_user("approver-1", "证据采信审批人", "approver")
            service.create_user("auditor-1", "审计人员", "auditor")
            service.register_device("operator-1", "device-a", "A 型事故证据采集设备", "示例设备供应商")
            service.register_build("operator-1", "build-a1", "device-a", "1.0.0", "a" * 64)
            service.publish_evidence_protocol("stat-1", evidence_protocol)
            service.create_batch("operator-1", "batch-demo", evidence_protocol["evidence_protocol_id"], evidence_protocol["version"], "build-a1")
            service.start_batch("operator-1", "batch-demo", 1)
            imported = service.import_evidence_items(
                "operator-1", "batch-demo", "demo-import-1", evidence_item_rows
            )
            service.seal_batch("stat-1", "batch-demo", 2)
            job = service.claim_job("worker-1", lease_seconds=60)
            if job is None:
                raise RuntimeError("未能领取分析任务")
            analysis = service.complete_job("worker-1", job["job_id"], "stat-1")

            # 物证保管链：登记封存、双方交接、重新封装、依法调阅与归还。
            custody = CustodyService(connection)
            custody.register_location("operator-1", "vault-01", "中心物证库房 01 柜", "vault")
            custody.register_location("operator-1", "room-review-01", "复核阅卷室", "room")
            custody.register_material(
                "operator-1", "mat-demo-1", "事故现场原始视频", "video", "vault-01",
                "c" * 64, "d" * 64, 4096, "video/mp4", "现场封存首版",
                batch_id="batch-demo",
            )
            transfer = custody.propose_transfer(
                "operator-1", "mat-demo-1", "operator-2", "vault-01", "移交复核"
            )
            accepted = custody.respond_transfer(
                "operator-2", transfer["transfer_id"], True, "封装完好，核对无误"
            )
            if accepted["state"] != "accepted":
                raise RuntimeError("交接未被接收确认")
            custody.reseal(
                "operator-2", "mat-demo-1", "e" * 64, "approver-1", "复核后双人见证重新封装"
            )
            access = custody.request_access(
                "operator-2", "mat-demo-1", "代理律师张某", "13800001111",
                "道路交通事故处理程序规定第六十五条", "申诉阶段阅卷"
            )
            decided_access = custody.decide_access(
                "approver-1", access["request_id"], True, "同意依法调阅", "2026-09-30T18:00:00Z"
            )
            custody.checkout_access("operator-2", access["request_id"], "登记后交付阅卷")
            custody.return_access("operator-2", access["request_id"], "vault-01", "阅后归还入库")
            if decided_access["state"] != "approved":
                raise RuntimeError("调阅申请未获批准")

            decision_value = "approved" if analysis["result"]["conclusion"] == "pass" else "rejected"
            decision_result = service.decide(
                "approver-1", "batch-demo", analysis["analysis_id"], decision_value, "离线验收决定"
            )
            # 责任认定后再上传必须被拒绝。
            try:
                custody.upload_version(
                    "operator-1", "mat-demo-1", "f" * 64, "0" * 64, 2048, "试图覆盖已认定版本"
                )
                raise RuntimeError("责任认定后仍允许上传新版本")
            except InvalidState:
                pass
            auditor_chain = custody.chain_view("auditor-1", "mat-demo-1")
            masked_chain = custody.chain_view("stat-1", "mat-demo-1")
            if not auditor_chain["verification"]["intact"]:
                raise RuntimeError("审计视角保全链校验失败")
            if auditor_chain["access_requests"][0]["requester_contact"] != "13800001111":
                raise RuntimeError("审计人员应能看到调阅人联系方式明文")
            if masked_chain["access_requests"][0]["requester_contact"] == "13800001111":
                raise RuntimeError("非授权角色看到了调阅人联系方式明文")
            report = service.report("auditor-1", "batch-demo")
            schema = inspect_schema(connection)
        finally:
            connection.close()
    if schema["missing_tables"] or schema["schema_version"] != "3":
        raise RuntimeError("SQLite 基础结构检查失败")
    return {
        "status": "ok",
        "evidence_protocol": f"{evidence_protocol['evidence_protocol_id']}@{evidence_protocol['version']}",
        "evidence_item_count": imported["inserted"],
        "analysis_id": analysis["analysis_id"],
        "input_sha256": analysis["input_sha256"],
        "conclusion": analysis["result"]["conclusion"],
        "decision": report["decision"]["decision"],
        "event_count": len(report["events"]),
        "custody_event_count": len(auditor_chain["events"]),
        "custody_chain_intact": auditor_chain["verification"]["intact"],
        "custody_locked_materials": decision_result["locked_materials"],
        "custody_masked_contact": masked_chain["access_requests"][0]["requester_contact"],
        "schema": schema,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="执行校准数据基础工具的离线自检")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    result = run(args.workspace.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
