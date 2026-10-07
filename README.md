# 防篡改本地审计事件流水线（Tamper-Evident Audit Pipeline）

一个可在本地完整复现的 Spring Boot 服务：把**多来源审计事件**接入、归一化，写入**防篡改只追加账本**，
并通过 **outbox + 重试调度器**可靠转发；同时支持**保留策略、法律保留与合规清除**。
所有关键结论（拒绝原因、篡改位置、保留/清除依据、重试类别）都可解释、可测试。

---

## 1. 架构与数据流

```
HTTP POST /audit/events
        │
        ▼
 EventNormalizer  ──校验失败──▶ RejectReason（MALFORMED_JSON / MISSING_REQUIRED_FIELD /
        │                       FIELD_TYPE_MISMATCH / INVALID_TIMESTAMP / SUSPICIOUS_TIMESTAMP）
        ▼
 稳定幂等键 sha256(source:eventId)
        │
        ▼
 AppendOnlyLedger（哈希链 + 每记录 AES-GCM + 独立 DEK + CRC + 序号无空洞 + force 落盘）
        │ 追加成功后
        ▼
 OutboxStore（PENDING→INFLIGHT→SENT/DEAD，逐行 fsync）
        │
        ▼
 RetryDispatcher（按序认领、指数退避、错误分类、死信、重启从最小未完成位置继续）
        │
        ▼
 HttpForwarder（Idempotency-Key 头透传，接收端去重 → 有效一次）

POST /audit/retention/enforce   ── RetentionService（法律保留 > 合规清除 > 到期清除；加密擦除）
POST /audit/compliance/purges   ── CompliancePurgeService（请求标识/原因、按主体或序号范围、
│                                                  预演 dryRun、幂等、逐记录可解释）
POST /audit/verify              ── 全量/分段完整性核验（CHECKPOINT 锚点，读盘结论与重启一致）
POST/DELETE /audit/holds        ── LegalHoldService（法律保留登记/解除）
```

存储目录（默认 `data/audit/`，由 `audit.storage-dir` 配置）：

| 文件 | 内容 |
|---|---|
| `ledger.log` | 逐行 JSON 帧（DATA / PURGE / CHECKPOINT / UPGRADE），只追加，哈希链 |
| `ledger.log.anchor` | 外部锚点：最后帧位/序号/tailHash/CHECKPOINT 偏移/兼容边界，自带 HMAC，原子替换写盘 |
| `keys/<seq>.key` | 每条记录独立的 256 位 DEK；删除该文件即加密擦除 |
| `keys/hmac.key` | 哈希链与锚点 HMAC 密钥（位于账本之外，仅属主可读写） |
| `outbox.log` | 转发发件箱事件日志，重放重建状态 |
| `holds.log` | 法律保留 ADD/REMOVE 事件日志 |
| `compliance-requests.log` | 合规清除请求指纹（REQ）与首次结果（RESULT），支撑重启后仍幂等 |

---

## 2. 事件接入与归一化规则

必填字段（缺失或空白 → **MISSING_REQUIRED_FIELD**；类型错误 → **FIELD_TYPE_MISMATCH**）：

- `source`、`eventId`、`eventType`：非空字符串
- `occurredAt`：epoch 毫秒数字 **或** ISO-8601 字符串
  - 无法解析、负数（早于 1970）→ **INVALID_TIMESTAMP**
  - 晚于 `now + audit.max-future-skew-ms` → **SUSPICIOUS_TIMESTAMP**（时钟异常不静默丢弃）

可选字段的**确定性默认语义**（向后兼容）：

- `severity` 缺失/空白 → `"INFO"`；非空则 trim + 大写归一
- `subject` 缺失 → `""`
- `extensions` 必须是对象，否则 FIELD_TYPE_MISMATCH

**未知扩展字段不抹掉**：所有非保留字段，以及 `extensions` 内字段，统一并入归一化后的 `extensions` 落库与转发。

**幂等**：`idempotencyKey = sha256(source + ":" + eventId)`。重复提交返回 `accepted=true, duplicate=true`
与首次相同的 `sequence`，不会重复写入或重复转发。

---

## 3. 防篡改只追加留存（v2：外部锚点 + 分段锚 + 懒解密）

### 3.1 磁盘形态

每条 DATA 帧含：`pos`（帧位）、`seq`（数据序号，唯一无空洞）、幂等键、写入时间、事件时间、
密文 `body`、CRC32、`prev`、HMAC `hash`。追加在锁内串行、写完 `force(true)` 落盘。

除 DATA / PURGE 外，v2 还有两类帧：

- `CHECKPOINT` 帧：`{pos, kind=CHECKPOINT, afterDataSeq, prev, hash}`，默认每 1000 条 DATA 出现一次
  （可用 JVM 系统属性 `-Daudit.ledger.checkpointInterval=N` 调整）。它占帧位、不占数据序号，
  是“只核验一段”的起点锚。
- `UPGRADE` 帧：老目录首次以新版本打开时追加的升级边界标记。

账本同目录下还有一个**外部锚点文件** `ledger.log.anchor`（原子替换写盘，含自身 HMAC）：

```json
{"pos": 最后帧位, "dataSeq": 最后数据序号, "tailHash": 最后一帧hash,
 "legacy": 是否老目录升级, "boundaryDataSeq": 升级边界序号,
 "checkpoints": [{"after","pos","offset","hash"}, ...], "hmac": "..."}
```

HMAC 密钥仍在账本之外（`keys/hmac.key`）。锚点的意义：**删除末尾完整记录、把最后一条截成半行
之类不改动任何“存活帧”的攻击，只靠哈希链无法发现，靠锚点对账才能在重启后依然判出来**，
结论不依赖任何运行期内存状态。

### 3.2 覆盖的破坏类型与“最早受影响序号”定义

打开账本与运行期核验都会逐帧做 CRC + HMAC + `prev` + 帧位 + 数据序号连续性校验，并与锚点对账：

| 破坏类型 | 判定依据 | firstTamperedSequence |
|---|---|---|
| 改动某条记录内容（密文/字段） | CRC/HMAC 不匹配 | 被改记录自身序号 |
| 删除中间任意一条 | 数据序号出现空洞 | **删除后第一个空缺序号** |
| 删除末尾一条或连续多条 | 锚点 `pos/dataSeq` 大于实际完整帧 | 被删连续段的第一条（第一个空缺） |
| 相邻两条互换 | 两帧的 seq/pos/prev/HMAC 全部失配 | **互换两条中序号较小者** |
| 最后一条只写一半（半行截断） | 物理不完整尾部截断后锚点对账缺失 | 被截断的那条序号 |
| 未经 PURGE 私删 DEK | DEK 文件缺失且无清除标记 | 该记录序号 |

“最早受影响”统一取**所有失配/空缺对应数据序号的最小值**；因此它永远指向破坏开始的位置，
而不是第一个“看起来不对的存活帧”。结论在 `停服 → 改文件 → 重开` 后完全一致：
破坏状态与位置持久化在文件与锚点中，不在内存里。

一旦判定破坏：

- 账本进入 **closed**：后续新的事件追加、到期清除、合规清除（含预演）一律明确拒绝，
  错误体带 `reason=LEDGER_TAMPERED` 与 `firstTamperedSequence`（HTTP 503）；
- 服务以只读降级模式保持在线，`GET /audit/state` 返回 `ledgerClosed/healthy=false`、
  最早受影响位置、兼容边界与清除统计；
- 破坏后再调用任何核验，结论保持“破坏”，不会因只扫存活帧而被洗白；
  分段核验时，破坏点落在区间内必报、落在区间外的区间仍可判健康。

直接使用 `new AppendOnlyLedger(path)` 的嵌入式用法 fail-fast 抛出 `TamperException`；
服务装配走 `openDegraded` 提供可观测的拒绝响应。

### 3.3 大账本与并发：快速恢复、分段核验

- **懒解密**：重启恢复只做线性 HMAC 校验，不逐条解密；明文在首次被读取时才用 DEK 解密并缓存。
  30,000 条记录的重启恢复与全量核验均为线性开销（单测实测秒级以内）。
- **分段核验**：`POST /audit/verify` 带 `fromSeqInclusive/toSeqInclusive` 时，只从区间之前最近的
  CHECKPOINT 锚点开始有界扫描（内存版与直接读盘版结论一致；读盘版不依赖本次进程内存，
  使用锚点中持久化的 CHECKPOINT 字节偏移定位）。把区间按锚点拼满整个账本，结论与一次性全量核验相同。
- **并发**：追加与核验共用账本锁；并发追加进行中反复全量/分段核验不会误报稳定历史，
  并发结束后全量核验必须健康、序号无空洞。

### 3.4 老数据目录的兼容范围与升级

上一轮版本（v1，只有 DATA/PURGE、无锚点、无 CHECKPOINT）写过数据的目录，用新版本打开：

1. 先按帧完整重放校验；老数据链本身完整就**不会**因为缺少新字段被当成损坏，可继续追加与核验；
2. 非空老目录追加一条 `UPGRADE` 帧标记升级边界，并写入首版锚点；`GET /audit/state` 中
   `legacyMode=true`、`legacyBoundaryDataSeq=N` 明确给出兼容结论与范围；
3. **兼容边界（能力限制，显式告知而非悄悄降级）**：升级前的历史链可完整验证，
   但“删除升级边界之前的末尾整段”在没有锚点的时代无从证明，不在新核验能力覆盖范围内；
   `UPGRADE` 之后写入的所有记录立即具备完整保护（含末尾删除检测）。若检测到 `UPGRADE` 帧却
   缺失锚点文件，视为“删除锚点回退”，直接判破坏，防止攻击者把账本退回无锚点状态。
4. 旧格式 PURGE 帧（无 `source/requestId`、旧 HMAC 公式）仍按旧公式兼容校验，来源记为 `RETENTION`。

### 3.5 保留、法律保留与合规清除的仲裁

三种清除/保留意图的优先级（每条记录都给出可解释结论）：

1. **法律保留（最高）**：记录 `subject` 命中任一 hold 子串模式 → 任何来源都不得清除
   （`BLOCKED_BY_LEGAL_HOLD`）；
2. **合规清除**：`POST /audit/compliance/purges` 主动发起，按主体或序号范围命中、
   未被 hold 挡住的记录一律清除——**即使它本来就快到期，也按合规清除处理（来源 COMPLIANCE）**，
   不需要等到期任务；
3. **保留到期**：`POST /audit/retention/enforce`，`occurredAt < now-retentionDays` 且未命中 hold
   才清除（边界 `== cutoff` 保留），来源 `RETENTION`；
4. 已清除记录不再重复处理，只在结果中回报 `ALREADY_PURGED` 与历史来源。

**合规清除请求**：`{requestId, reason, subjectPattern?, fromSeqInclusive?, toSeqInclusive?, dryRun?}`
（两个选择器至少给一个，可同时给表示交集）。

- `dryRun=true` 为**预演**：返回每条命中记录“将被清/会被法律保留挡下/此前已清”的完整结论，
  但**不改动任何留存内容、不写幂等记录**；预演清单与随后正式执行清单一致。
- 同一 `requestId` 重复提交正式请求：第二次起返回 `idempotentReplay=true` 与首次完全相同的结论，
  不重复清除、不产生额外 PURGE 帧（幂等状态持久化在 `compliance-requests.log`，重启仍有效）。
- 同一 `requestId` 携带不同请求体 → `DUPLICATE_REQUEST_ID_CONFLICT`（HTTP 409）。

清除方式仍是**加密擦除**：在哈希链内追加带 `source/requestId/reason` 的 PURGE 帧后删除该记录 DEK。
原始明文此后密码学上不可恢复，但“这条记录存在过、在何时因何请求被谁清除”随链永久可审计、可证明。

法律保留通过 `POST /audit/holds`（`holdId`/`subjectPattern`/`reason`）登记，
`DELETE /audit/holds/{holdId}` 解除；解除后合规/到期清除即可正常生效。

---

## 4. 转发失败分类与重试语义

`HttpForwarder` 的归类：

| 情况 | 结论 | errorCategory 示例 |
|---|---|---|
| 2xx | SUCCESS → `SENT`（终态，不重复转发） | — |
| 408 / 429 / 5xx | RETRYABLE | `HTTP_429`、`HTTP_503`、`HTTP_408` |
| 其它 4xx | NON_RETRYABLE → 直接 `DEAD` 死信 | `HTTP_400`、`HTTP_404` |
| 连接拒绝/网络 IO | RETRYABLE | `CONNECT_REFUSED`、`NETWORK` |
| 超时 | RETRYABLE | `TIMEOUT` |
| 未配置地址 / 非法 URL / 未预期异常 | NON_RETRYABLE | `NOT_CONFIGURED`、`BAD_ENDPOINT`、`UNEXPECTED` |

- **不丢**：账本追加后才登记 outbox；若崩溃在两步之间，重启时 `repairOutbox()` 按账本补登记。
- **不重（业务意义）**：outbox id = 账本序号，重复登记返回同一条目；
  SENT/DEAD 为终态；每次 HTTP 请求带 `Idempotency-Key`，接收端去重后为有效一次投递。
- **退避**：`min(initialDelay * 2^(attempt-1), maxDelay)`，无抖动、确定性；超过最大次数 → `DEAD(RETRIES_EXHAUSTED)`。
- **重启可预期继续**：INFLIGHT 超过 `audit.inflight-recover-ms` 视为旧派发器崩溃，可被重新认领；
  重投顺序按 outbox id 升序，`OutboxStore.resumePosition()` 即“最小未完成位置”（无未完成时为 -1）。

---

## 5. 配置项（`application.properties` 前缀 `audit`）

| 配置 | 默认 | 说明 |
|---|---|---|
| `audit.storage-dir` | `data/audit` | 账本/outbox/holds/密钥目录 |
| `audit.max-future-skew-ms` | `60000` | occurredAt 允许超过当前时间的毫秒数 |
| `audit.retention-days` | `90` | 保留天数（事件时间基准，边界保留） |
| `audit.auto-forward` | `false` | 启动后是否自动开始后台重试派发 |
| `audit.forward-url` | （空） | 转发目标；为空时转发判为 NOT_CONFIGURED |
| `audit.forward-timeout-ms` | `5000` | 单次 HTTP 超时 |
| `audit.retry-max-attempts` | `10` | 最大尝试次数，超过进死信 |
| `audit.retry-initial-delay-ms` | `200` | 首次退避 |
| `audit.retry-max-delay-ms` | `30000` | 退避上限 |
| `audit.dispatch-interval-ms` | `500` | 自动派发轮询间隔 |
| `audit.inflight-recover-ms` | `30000` | INFLIGHT 卡死回收阈值 |

---

## 6. HTTP 接口

| 方法/路径 | 作用 |
|---|---|
| `POST /audit/events` | 接入事件。200=接受（新/重复）；400=分类拒绝（body 内 `reason`/`detail`）；503=账本破坏关闭 |
| `GET /audit/state` | 只读状态：是否健康/关闭、最早受影响序号、记录数、下一序号、outbox 重投位置、`legacyMode`/`legacyBoundaryDataSeq` 兼容边界、按来源统计的清除数 |
| `POST /audit/verify` | 完整性核验。空 body 或 `{}`=全量；带 `fromSeqInclusive/toSeqInclusive`=分段（有界扫描，返回锚点与帧数） |
| `POST /audit/retention/enforce` | 执行保留到期清除，返回三类序号清单与策略描述 |
| `POST /audit/compliance/purges` | 主动合规清除（支持 `dryRun` 预演；按 requestId 幂等；冲突 409） |
| `POST /audit/holds` | 登记法律保留 |
| `DELETE /audit/holds/{holdId}` | 解除法律保留 |

事件响应例：

```json
{ "accepted": true, "duplicate": false, "sequence": 12,
  "idempotencyKey": "ab12...", "reason": null, "detail": null }
```

---

## 7. 本地验证方法

### 7.1 运行测试（并发追加 / 篡改 / 重投 / 保留边界 / 字段兼容）

```bash
mvn clean test
```

关键测试类（共 73 个用例，均打印“输入 / 判定依据 / 最终状态”日志）：

- `EventNormalizerTest`：必填/类型/时间异常分类、默认值、未知字段保留、幂等键稳定
- `AppendOnlyLedgerTest`：无空洞、重放、半帧截断（崩溃撕裂老语义）、篡改定位与 closed、私删 DEK、加密擦除
- `LedgerV2TamperDetectionTest`：**改内容/删中间/删末尾一条/删末尾连续/相邻互换/半行截断**六类破坏的
  检测与“最早受影响”定位；重启复判一致；破坏后追加/到期清除/合规清除全拒绝、状态可查
- `LegacyLedgerUpgradeTest`：v1 目录升级不被误判、继续追加核验、兼容边界可解释、旧 PURGE 帧兼容、空目录全能力
- `SegmentVerifyAndScaleTest`：分段（内存+读盘）拼接与全量一致、破坏段精确定位且相邻段不误报、
  30,000 条线性恢复/核验耗时、只核末段 2000 条
- `ConcurrentAppendVerifyTest`：8 写线程并发追加 2400 条 + 2 线程反复全量/分段核验，零误报、序号无空洞、重启一致
- `CompliancePurgeServiceTest`：预演/执行一致且预演零改动、法律保留挡下、重复请求幂等（含重启）、
  同 ID 冲突、合规优先于到期、已清不重复、主体子串选择、清除可审计且明文不可恢复、破坏后拒绝、
  中文原因 + PURGE 穿插分段的读盘核验
- `CompliancePurgeWebIntegrationTest`：合规清除 HTTP 生命周期（预演/执行/幂等/409/核验/状态）
- `ConcurrentAppendTest`：16 线程×100 唯一无空洞；200 并发相同事件恰好 1 落库；300 不同事件全接受
- `RetentionServiceTest`：cutoff ±1 分钟边界、法律保留优先、解除后可清除、清除幂等
- `RetryDispatcherTest`：成功不重复、可重试退避、不可重试死信、次数耗尽、按序与 resumePosition、崩溃 INFLIGHT 回收
- `HttpForwarderTest`：200/408/429/4xx/5xx/连接拒绝/未配置 的错误归类
- `PipelineEndToEndTest`：重启幂等、outbox 补登记、篡改后拒绝新追加、真实 HTTP 成功/500 重投/400 死信
- `WebApiIntegrationTest`：HTTP 状态码与 MALFORMED_JSON 映射

查看某条用例的判定日志：

```bash
mvn -Dtest=LedgerV2TamperDetectionTest test | grep -F "[CASE"
cat target/surefire-reports/*LedgerV2TamperDetectionTest.txt
```

### 7.2 手工复现

```bash
# 终端 A：启动服务（auto-forward=false，离线即可复现留存/清除）
mvn spring-boot:run

# 终端 B：
curl -s -XPOST localhost:8080/audit/events -H 'Content-Type: application/json' \
  -d '{"source":"web","eventId":"e-1","eventType":"login","occurredAt":"2026-09-01T10:00:00Z","device":"mobile"}'
curl -s -XPOST localhost:8080/audit/events -H 'Content-Type: application/json' \
  -d '{"source":"web","eventId":"e-1","eventType":"login","occurredAt":"2026-09-01T10:00:00Z"}'   # duplicate=true
curl -s -XPOST localhost:8080/audit/events -H 'Content-Type: application/json' -d '{"source":"x"}'  # MISSING_REQUIRED_FIELD

# 法律保留 + 合规清除
curl -s -XPOST localhost:8080/audit/holds -H 'Content-Type: application/json' \
  -d '{"holdId":"h1","subjectPattern":"vip","reason":"诉讼"}'

# 1) 预演（dryRun=true）：只告诉你会清哪些、哪些被法律保留挡下，不动任何数据
curl -s -XPOST localhost:8080/audit/compliance/purges -H 'Content-Type: application/json' \
  -d '{"requestId":"gdpr-001","reason":"用户行使删除权","fromSeqInclusive":1,"toSeqInclusive":100,"dryRun":true}'
# 2) 正式执行（同一 requestId，结论与预演一致）
curl -s -XPOST localhost:8080/audit/compliance/purges -H 'Content-Type: application/json' \
  -d '{"requestId":"gdpr-001","reason":"用户行使删除权","fromSeqInclusive":1,"toSeqInclusive":100}'
# 3) 重复提交：idempotentReplay=true，结论与首次完全一致，不重复清除
curl -s -XPOST localhost:8080/audit/compliance/purges -H 'Content-Type: application/json' \
  -d '{"requestId":"gdpr-001","reason":"用户行使删除权","fromSeqInclusive":1,"toSeqInclusive":100}'
# 按主体清除：'{"requestId":"...","reason":"...","subjectPattern":"alice"}'

# 到期清除（受法律保留与合规状态仲裁）
curl -s -XPOST localhost:8080/audit/retention/enforce
# 全量 / 分段核验
curl -s -XPOST localhost:8080/audit/verify -H 'Content-Type: application/json' -d '{}'
curl -s -XPOST localhost:8080/audit/verify -H 'Content-Type: application/json' \
  -d '{"fromSeqInclusive":1001,"toSeqInclusive":2000}'
curl -s localhost:8080/audit/state

# 破坏演示：停服后任选一种改法，再启动
#   a) 改 data/audit/ledger.log 任意帧的 body 字符
#   b) 删除文件末尾一行（删除末尾完整记录）
#   c) 删除中间任意一行；d) 交换相邻两行；e) 把最后一行截掉一半（不留换行）
# → 服务以只读降级模式启动；GET /audit/state 显示 healthy=false 与 firstTamperedSequence
# → 新事件接入、到期清除、合规清除均返回 LEDGER_TAMPERED(503)；POST /audit/verify 结论一致
```

> 注意 `server.port=0` 仅用于测试随机端口；手工复现可在命令行加
> `mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8080`。

### 7.3 转发/重投复现

配置 `audit.forward-url` 指向接收端（或测试中的 JDK HttpServer），置 `audit.auto-forward=true`。
接收端依据 `Idempotency-Key` 去重；返回 500/429 可观测指数退避重投，返回 400 观察立即死信。
进程在 INFLIGHT 期间 kill -9，重启后从 `resumePosition()` 继续，不会跳过也不会产生业务重复。

---

## 8. 设计边界与说明

- 威胁模型假设攻击者可改/删账本文件，但**拿不到** `keys/hmac.key` 与 DEK（文件权限尽力设为仅属主）。
  HMAC 密钥泄露后链与锚点都不再具备防篡改能力——生产环境应把 HMAC 根密钥放入 KMS/HSM。
  此外，能同时改写 `ledger.log` 与 `ledger.log.anchor` 的攻击者可伪造锚点；因此锚点文件应与账本
  分开保护（不同权限域/备份域），后续可演进为把锚点尾部证明写入外部只追加见证。
- 合规/到期清除都通过删除独立 DEK 实现加密擦除：密文与 envelope 保留可审计，但密码学上不可恢复明文；
  PURGE 帧带来源（`RETENTION`/`COMPLIANCE`）、`requestId` 与 `reason`，清除事实本身随链留存。
- **老目录兼容边界**：升级只追加 `UPGRADE` 帧与锚点，不改动历史帧；升级前历史的帧内篡改/删中间仍可检出，
  但“删除升级前末尾整段”在无锚点时代无法证明，这一范围通过 `legacyMode/legacyBoundaryDataSeq` 明确告知。
- 崩溃时帧已落盘而锚点未及更新：重开后链校验通过即补齐锚点，不误判；
  锚点领先于实际文件（删帧/半行）才判破坏。物理不完整尾部对 v2 账本结合锚点判定（判破坏），
  对尚未升级的老目录沿用“截断后继续”的旧行为。
- 转发为 **at-least-once + 接收端幂等 = 有效一次**；接收端必须持久化 `Idempotency-Key` 去重。
- 所有时间/退避逻辑不使用随机抖动，保证测试与行为的确定性。
