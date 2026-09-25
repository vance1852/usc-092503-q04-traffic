# 道路交通事故快处与处罚协同服务

本项目是一套可离线运行的 Python 后台，用于事故受理、道路风险研判、警力与拖车调度、结构化证据复核、证据保全链管理、责任认定、处罚执行和审计追溯。系统把同一事故从报警到结案的关键状态保存在 SQLite 中，角色权限覆盖接警员、调度员、事故处理民警、证据采集员、证据保管员、复核人员和审计人员。

## 目录

- `src/traffic_dispatch/`：事故风险指数、快处中心、道路走廊、应急资源、调度申请和响应情景；
- `src/evidence_review/`：采集设备、证据规范、结构化记录导入、一致性分析、复核租约和采信决定；
- `src/evidence_custody/`：证据包登记、不可变内容摘要、保管位置、限定角色双人确认交接、拒收/遗失/重新封装/依法调阅的连续状态、责任认定版本锁定、保全链查询与断链定位；
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
PYTHONPATH=src python3 -m evidence_custody.acceptance --workspace .
PYTHONPATH=src python3 -m penalty_ops.acceptance
```

验收会建立临时 SQLite 数据库，登记事故风险记录、快处中心、道路走廊和应急资源，完成调度与证据复核，并输出 JSON 结果。命令不会访问公网，也不需要额外数据库、队列或常驻服务。

## HTTP API

```bash
PYTHONPATH=src python3 -m traffic_dispatch.api --database traffic.sqlite3 --host 127.0.0.1 --port 8080
PYTHONPATH=src python3 -m evidence_review.api --database evidence.sqlite3 --host 127.0.0.1 --port 8081
PYTHONPATH=src python3 -m penalty_ops.api --database penalties.sqlite3 --host 127.0.0.1 --port 8082
PYTHONPATH=src python3 -m evidence_custody.api --database custody.sqlite3 --host 127.0.0.1 --port 8083
```

四个服务均提供 `GET /health`，其余接口使用 JSON。SQLite 文件保存业务状态、幂等结果和审计记录，进程重启后可继续查询。

## 证据保全链

`evidence_custody` 覆盖采集员、保管员、办案人员、复核人员和审计人员五类角色：

- 证据包登记时封存首个版本并生成哈希链创世环节，之后每次上传只追加新版本号，版本行只增不改；责任认定登记会快照所依据版本的摘要，该版本此后不得被覆盖，申诉补充材料只能形成更高版本；
- 交接由当前保管人发起、接收人确认，双方都必须属于限定角色（采集员/保管员/办案人员/复核人员），接收时须核验内容摘要，不符只能拒收并说明原因；
- 拒收、遗失、重新封装和依法调阅（须登记法律文书编号）都会作为链上环节改变保管状态，状态机保证环节连续；
- `GET /packages/{id}/chain` 向办案人员展示完整保全链和明文联系方式，其他角色只能看到遮蔽后的联系方式；`GET /packages/{id}/verify` 重放整条链，指出序号断裂、前向哈希不符、事件被篡改、版本摘要被覆盖或台账与链推导不一致的具体环节。
