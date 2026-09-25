# 道路交通事故快处与处罚协同服务

本项目是一套可离线运行的 Python 后台，用于事故受理、道路风险研判、警力与拖车调度、结构化证据复核、责任认定、处罚执行和审计追溯。系统把同一事故从报警到结案的关键状态保存在 SQLite 中，角色权限覆盖接警员、调度员、事故处理民警、复核人员和审计人员。

## 目录

- `src/traffic_dispatch/`：事故风险指数、快处中心、道路走廊、应急资源、调度申请和响应情景；
- `src/evidence_review/`：采集设备、证据规范、结构化记录导入、一致性分析、复核租约、采信决定，以及物证保管链（内容摘要、保管位置、逐次交接、依法调阅与防篡改校验）；
- `src/penalty_ops/`：事故案件、违法记录、风险告警、处置工单、处罚流转和审计；
- `fixtures/`：离线验收使用的证据规范与结构化事故记录；
- `tests/`：领域规则、事务边界、权限、HTTP API 和 CLI 验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅依赖 Python 标准库与 SQLite

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -q
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m traffic_dispatch.acceptance --workspace .
PYTHONPATH=src python3 -m evidence_review.acceptance --workspace .
PYTHONPATH=src python3 -m penalty_ops.acceptance
```

验收会建立临时 SQLite 数据库，登记事故风险记录、快处中心、道路走廊和应急资源，完成调度与证据复核，并输出 JSON 结果。命令不会访问公网，也不需要额外数据库、队列或常驻服务。

## HTTP API

```bash
PYTHONPATH=src python3 -m traffic_dispatch.api --database traffic.sqlite3 --host 127.0.0.1 --port 8080
PYTHONPATH=src python3 -m evidence_review.api --database evidence.sqlite3 --host 127.0.0.1 --port 8081
PYTHONPATH=src python3 -m penalty_ops.api --database penalties.sqlite3 --host 127.0.0.1 --port 8082
```

三个服务均提供 `GET /health`，其余接口使用 JSON。SQLite 文件保存业务状态、幂等结果和审计记录，进程重启后可继续查询。

## 物证保管链

`evidence_review` 在结构化复核之外维护原始材料的不可变保全链（见 `src/evidence_review/custody.py`）：

- **不可变摘要**：每份材料登记内容 SHA-256 与封装 SHA-256；重新封装只更新封装摘要，内容摘要不变。版本表只追加，后续上传永远产生新版本，不覆盖旧版本。
- **连续状态**：封存（sealed）→ 交接中（in_transfer）→ 入库（stored）/拒收（rejected），以及遗失（lost）/找回、重新封装（resealed）、依法调阅（access_pending/accessed）/归还/到期失效。任何状态变化都向哈希链追加一环，事件哈希覆盖序号、前一环哈希、负载、摘要与时间，链尾与主档相互锚定。
- **限定角色的双方确认**：交接由当前持有人发起、指定接收人确认或拒收；接收人必须属于具备接收权限的角色，申请人不能确认自己的交接。
- **责任认定锁定**：批次形成 approved/rejected 决定前会重放关联材料的保全链，链不完整或摘要不一致则拒绝认定；认定通过后材料版本锁定，`upload_version`/重新封装一律拒绝。
- **按权限遮蔽**：调阅人联系方式仅 auditor 可见明文，其他角色得到脱敏值（如 `1*********1`），原始存储不被改写。
- **断裂定位**：`GET /custody/materials/{id}/chain` 与批次报告均返回 `verification`，逐条给出异常的 `code` 与 `sequence_no`（链断裂、事件哈希不一致、内容/封装摘要不一致、状态机非法迁移、链尾篡改、锁定后补版等）。

保管链接口（均需 `X-Actor-Id`）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/custody/locations` | 登记保管位置 |
| POST | `/custody/materials` | 登记封存材料（内容与封装摘要） |
| POST | `/custody/materials/{id}/versions` | 追加后续版本（不覆盖） |
| POST | `/custody/materials/{id}/transfers` | 持有人发起交接 |
| POST | `/custody/transfers/{id}/respond` | 接收人确认/拒收 |
| POST | `/custody/transfers/{id}/cancel` | 交出方撤销交接 |
| POST | `/custody/materials/{id}/loss`、`/found`、`/reseal` | 遗失、找回、重新封装 |
| POST | `/custody/materials/{id}/access_requests` | 依法调阅申请 |
| POST | `/custody/access_requests/{id}/decide|checkout|return|expire` | 审批、出库、归还、到期 |
| POST | `/custody/materials/{id}/lock` | 责任认定锁定（approver） |
| GET | `/custody/materials/{id}/chain` | 完整保全链、版本、交接、调阅与校验结论 |
| GET | `/custody/materials?batch_id=` | 按批次列出材料 |
