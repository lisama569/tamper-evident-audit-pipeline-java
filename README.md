# 防篡改本地审计事件流水线（Tamper-Evident Audit Pipeline）

一个可在本地完整复现的 Spring Boot 服务：把**多来源审计事件**接入、归一化，写入**防篡改只追加账本**，
并通过 **outbox + 重试调度器**可靠转发；同时支持**保留到期清除、法律保留与可主动发起的合规清除**。
所有关键结论（拒绝原因、篡改类型与最早受影响位置、保留/清除依据、重试类别）都可解释、可测试、重启后一致。

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

POST /audit/retention/enforce            ── RetentionService（法律保留 > 合规清除 > 到期清除；加密擦除）
POST /audit/compliance/purge/preview     ── CompliancePurgeService（预演，不改留存，逐条可解释）
POST /audit/compliance/purge/execute     ── CompliancePurgeService（requestId 幂等，重启一致）
POST /audit/verify · /verify/range       ── 全量/分段完整性核验（签名锚点+检查点，结论重启一致）
POST/DELETE /audit/holds                 ── LegalHoldService（法律保留登记/解除）
```

存储目录（默认 `data/audit/`，由 `audit.storage-dir` 配置）：

| 文件 | 内容 |
|---|---|
| `ledger.log` | 逐行 JSON 帧（DATA / PURGE），只追加，哈希链 |
| `keys/<seq>.key` | 每条记录独立的 256 位 DEK；删除该文件即加密擦除 |
| `keys/hmac.key` | 哈希链 HMAC 密钥（位于账本之外，仅属主可读写） |
| `keys/intent.json` | **写入意图**（HMAC 签名，原子替换）：区分“自身崩溃半写”与“被中断/伪造的半条” |
| `keys/anchor.json` | **已提交锚点**（HMAC 签名）：记录已提交的尾部 pos/seq/hash，检测末尾整条删除 |
| `keys/format.json` | 账本格式版本（当前 v2）；缺失即按 v1 老目录处理并原地升级 |
| `keys/checkpoints/cp-<seq>.json` | 分段核验用签名检查点（默认每 1000 条 DATA 落一个） |
| `outbox.log` | 转发发件箱事件日志，重放重建状态 |
| `holds.log` | 法律保留 ADD/REMOVE 事件日志 |
| `purge-requests.log` | 合规清除请求参数、评估边界与首次结论（幂等依据，重启有效） |

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

## 3. 防篡改只追加留存

- 每条 DATA 帧含：`pos`（帧位）、`seq`（数据序号）、幂等键、写入时间 `stored`、事件时间 `eventTime`、
  密文 `body`、CRC32、`prev`、HMAC `hash`。
- HMAC 输入覆盖序号、幂等键、时间、**密文、CRC** 与前一帧 hash；因此
  **篡改、删除、重排任何一帧都会破坏链**。
- 追加在锁内串行完成，写完 `force(true)` 落盘；数据序号唯一、无空洞。
- **写入意图 + 已提交锚点（崩溃原子协议）**：写帧前先在 `keys/` 原子落一个 HMAC 签名的写入意图
  （APPEND/PURGE），帧 + 换行落盘后再原子推进已提交锚点、删除意图。
  - 重启时**有合法意图但帧未写完** → 判定为自身崩溃，截断半帧、回滚孤立 DEK，账本保持健康（无半条可见）；
  - **没有合法意图却出现能识别为帧片段的半条/来源不明完整帧** → 判定为破坏。
  - 与帧无关的杂散尾部字节（不含任何帧特征字段）仍按崩溃脏字节截断，避免磁盘脏数据造成误报。
- **破坏检测矩阵与“最早受影响序号”定义**（结论带 `tamperEvidence` 证据类型）：

  | 破坏手法 | evidence | 最早受影响序号 |
  |---|---|---|
  | 改动某条记录内容（body/字段） | `CONTENT_ALTERED` | 该条序号（HMAC/CRC 不匹配） |
  | 删除中间任意一条 | `MIDDLE_FRAME_MISSING` | 第一个空缺序号 |
  | 删除末尾一条/连续几条完整记录 | `TAIL_RECORDS_MISSING` | 被删之后的**第一个空缺位置**（比已提交锚点短） |
  | 相邻两条记录调换顺序 | `REORDERED` | 两条中**序号较小**的那条 |
  | 最后一条只写了一半（无合法意图） | `HALF_FRAME_TAIL` | 该半条对应序号 |
  | 未经 PURGE 流程私删 DEK | `CONTENT_ALTERED` | 该条序号 |

  同一位置多种证据并存时，报告优先级为 REORDERED &gt; MIDDLE_FRAME_MISSING &gt; TAIL_RECORDS_MISSING
  &gt; HALF_FRAME_TAIL &gt; UNEXPECTED_TAIL_FRAME &gt; CHAIN_TAMPERED &gt; CONTENT_ALTERED。
- **结论只来自磁盘**：破坏结论完全由账本文件 + `keys/` 下 HMAC 签名的锚点/意图/检查点重算，
  不依赖任何运行期内存；停服、改文件、再启动，结论与改之前推断一致。
- 发现破坏后：账本进入 **closed**；服务以**只读降级模式**保持在线（`GET /audit/state` 可见
  `ledgerClosed=true`、`tamperEvidence`、`firstTamperedSequence`、`tamperDetail`），
  此后**事件追加、合规清除、到期清除一律返回 `LEDGER_TAMPERED`（HTTP 503）**并带原因。
  直接 `new AppendOnlyLedger(path)` 的嵌入式用法仍 fail-fast 抛 `TamperException`。
- **分段核验**：DATA 序号区间 `[from,to]` 可只重算该段（起点用 `from-1` 的签名检查点，from=1 用创世空 hash），
  不必每次从头全量；多段拼起来的结论与一次性全量核验一致，结论显式带 `fromSequence/toSequence`。
  起点缺少签名检查点时返回明确错误（422），**不悄悄降级为全量**。
  并发追加期间做核验：帧快照与锚点在同一把锁内取，核验范围恰好是某个已提交前缀，
  既不会把健康账本误报为破坏，也不会漏掉真实破坏。

### 保留与合规清除（可解释优先级）

**优先级（从高到低）：法律保留 &gt; 合规清除 &gt; 保留到期 &gt; 未到期。**

1. **法律保留（最高）**：记录 subject 命中任一 hold 子串模式 → 无论多旧、无论是否被合规请求命中，一律不清。
2. **主动合规清除**：`POST /audit/compliance/purge/preview|execute`，带 `requestId` 与 `reason`，
   按 `subject`（子串）或 `fromSequence/toSequence`（闭区间；两者都给取交集）发起。
   命中且未被 hold 挡下的记录**即使还没到期也直接按 `COMPLIANCE` 来源清除**。
3. **保留到期**：`POST /audit/retention/enforce`，`cutoff = now - audit.retention-days`，
   `occurredAt < cutoff` 且未命中 hold → 按 `EXPIRY` 清除（边界 `==cutoff` 保留）。
4. **已清除不重复处理**：已被到期/合规清除的记录在后续结果中分别标注
   `ALREADY_PURGED_EXPIRY` / `ALREADY_PURGED_COMPLIANCE`，不再产生任何动作。

合规清除语义：

- **预演（dryRun）**：返回每条命中记录的决策（`WILL_PURGE` / `BLOCKED_BY_LEGAL_HOLD` /
  `ALREADY_PURGED_*`）与文字依据；**不写帧、不删 DEK**，不留改动。预演集合与执行集合一致。
- **幂等**：请求参数与首次评估边界（当时最大数据序号 `evalUpToSequence`）持久化到 `purge-requests.log`。
  同一 `requestId` 重复提交（含进程重启后）直接返回首次结论（`idempotentReplay` 语义，结论集完全一致），
  不会重复清除，也不会因后来新增记录产生额外处理；同 id 但选择器/原因不同 → `COMPLIANCE_REQUEST_CONFLICT`（409）。
  执行中途崩溃（部分 PURGE 帧已落盘、结论未写）时，重放会识别带本 requestId 的已完成部分并补清剩余记录，
  最终集合与一次成功一致。
- **清除后可审计**：清除方式为加密擦除——链内追加带 `source/requestId/reason/stored` 的 PURGE 帧后删除独立 DEK；
  envelope（序号/幂等键/hash/时间/事件时间）与链仍可验证，**明文不可恢复，但“这段历史存在过、
  何时因何被谁清除”仍可证明**。

法律保留通过 `POST /audit/holds`（`holdId`/`subjectPattern`/`reason`）登记，
`DELETE /audit/holds/{holdId}` 解除；解除后下一轮保留/合规执行即可正常清除。

### 老数据目录（v1）的兼容与升级

用新版本打开旧版本写出的目录（无 `keys/format.json`）：

1. 先按**旧版本 HMAC 串**（DATA 帧无 `eventTime`、PURGE 帧无 `source/requestId`）全链重放；
2. 全链通过才**原地升级**到 v2（写入 `format.json`、创世检查点与当前尾部锚点），可继续追加与核验，不报错；
3. 通过 `GET /audit/compatibility` 返回明确的**能力与限制范围**：
   - 能力：全链已验证；从升级提交点起末尾整删/半条/来源不明帧检测生效；新记录支持 COMPLIANCE/EXPIRY 区分；
   - 限制：升级之前若末尾整条记录已被删除，因无历史锚点无法追溯（保护从升级点开始）；
     v1 的 PURGE 帧按 `EXPIRY/RETENTION` 兼容标注、不补造合规请求标识。
4. 升级时若链本身已对不上，仍判破坏并 closed，**不悄悄降级、不强行升级**。

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
| `POST /audit/events` | 接入事件。200=接受（新/重复）；400=分类拒绝（body 内 `reason`/`detail`）；503=账本篡改关闭 |
| `GET /audit/state` | 只读状态：是否破坏关闭、证据类型、最早受影响序号与文字依据、记录数/帧数、下一序号、outbox 继续位置 |
| `POST /audit/retention/enforce` | 执行保留到期清除（EXPIRY），返回清除/hold/未到期清单 |
| `POST /audit/compliance/purge/preview` | 合规清除预演（不改动留存），返回每条记录的决策与依据 |
| `POST /audit/compliance/purge/execute` | 合规清除执行；同 requestId 幂等；409=同 id 参数冲突；503=账本破坏 |
| `POST /audit/verify` | 全量完整性核验，返回 healthy/证据/最早受影响序号/范围/帧数/依据 |
| `POST /audit/verify/range?from=&to=` | 分段核验，只重算指定序号区间（起点需有签名检查点） |
| `GET /audit/compatibility` | 老目录兼容/升级结论（能力与限制范围）；全新目录 `legacy=false` |
| `POST /audit/holds` | 登记法律保留 |
| `DELETE /audit/holds/{holdId}` | 解除法律保留 |

合规清除请求体：

```json
{ "requestId": "gdpr-2026-0001", "reason": "用户行使删除权",
  "subject": "alice", "fromSequence": null, "toSequence": null }
```

结果里 `items[]` 逐条给出 `sequence/decision/rationale/purgeSource`，`purgedSequences`、
`blockedByLegalHold`、`alreadyPurged`、`retainedSequences` 为汇总清单，`selector` 含评估边界。

事件响应例：

```json
{ "accepted": true, "duplicate": false, "sequence": 12,
  "idempotencyKey": "ab12...", "reason": null, "detail": null }
```

---

## 7. 本地验证方法

### 7.1 运行测试（并发追加 / 篡改矩阵 / 合规清除 / 重投 / 保留边界 / 字段兼容 / 老目录升级 / 大规模分段核验）

```bash
mvn clean test
```

本轮新增测试类（共 75 个用例，均打印“输入 / 判定依据 / 最终结论”日志）：

- `EventNormalizerTest`：必填/类型/时间异常分类、默认值、未知字段保留、幂等键稳定
- `AppendOnlyLedgerTest`：无空洞、重放、半帧脏字节截断、篡改定位与 closed、私删 DEK、加密擦除
- `TamperDetectionV2Test`：**内容篡改 / 删中间 / 删末尾一条 / 删末尾连续多条 / 相邻互换（定位较小序号）/
  真帧半条收尾（HALF_FRAME_TAIL）/ 杂散字节按崩溃撕裂 / 结论重启一致 / 破坏后追加与清除双拒绝**
- `CompliancePurgeServiceTest`：**预演零改动且与执行集合一致、法律保留挡下、幂等（含重启与新增记录边界）、
  同 id 参数冲突、合规高于到期、已清不重复且区分来源、破坏账本拒绝清除、范围选择器**
- `CompliancePipelineEndToEndTest`：**服务门面全链路、执行中途崩溃重放结论一致、破坏后接入/合规/到期清除全拒绝、state 可见**
- `LegacyLedgerUpgradeTest`：**手工构造 v1 账本（旧 HMAC 串）→ 打开升级 → 继续追加核验；v1 删尾帧后拒绝静默升级**
- `RangeAndScaleVerifyTest`：**分段=全量结论、检查点缺失明确报错、3 万条恢复/核验秒级、
  8 线程并发追加+100 次核验零误报、真破坏五轮不漏报**
- `ConcurrentAppendTest`：16 线程×100 唯一无空洞；200 并发相同事件恰好 1 落库；300 不同事件全接受
- `RetentionServiceTest`：cutoff ±1 分钟边界、法律保留优先、解除后可清除、清除幂等
- `RetryDispatcherTest`：成功不重复、可重试退避、不可重试死信、次数耗尽、按序与 resumePosition、崩溃 INFLIGHT 回收
- `HttpForwarderTest`：200/408/429/4xx/5xx/连接拒绝/未配置 的错误归类
- `PipelineEndToEndTest`：重启幂等、outbox 补登记、篡改后拒绝新追加、真实 HTTP 成功/500 重投/400 死信
- `ComplianceWebApiIntegrationTest`：**合规预演/执行/幂等/409、/audit/verify、state 扩展字段、/audit/compatibility**
- `WebApiIntegrationTest`：HTTP 状态码与 MALFORMED_JSON 映射

查看某条用例的判定日志：

```bash
mvn -Dtest=ConcurrentAppendTest#concurrentAppendsProduceUniqueGaplessSequences test \
  | grep -F "[CASE"
cat target/surefire-reports/*ConcurrentAppendTest.txt
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

# 法律保留 + 到期清除
curl -s -XPOST localhost:8080/audit/holds -H 'Content-Type: application/json' \
  -d '{"holdId":"h1","subjectPattern":"vip","reason":"诉讼"}'
curl -s -XPOST localhost:8080/audit/retention/enforce

# 主动合规清除：先预演（不改数据），再执行；同一 requestId 可安全重复提交
curl -s -XPOST localhost:8080/audit/compliance/purge/preview -H 'Content-Type: application/json' \
  -d '{"requestId":"gdpr-1","reason":"用户删除权","subject":"alice"}'
curl -s -XPOST localhost:8080/audit/compliance/purge/execute -H 'Content-Type: application/json' \
  -d '{"requestId":"gdpr-1","reason":"用户删除权","fromSequence":1,"toSequence":100}'
curl -s localhost:8080/audit/compatibility     # 老目录升级结论（全新目录 legacy=false）
curl -s -XPOST localhost:8080/audit/verify     # 全量核验
curl -s -XPOST 'localhost:8080/audit/verify/range?from=1001&to=2000'   # 分段核验（需检查点边界）

# 篡改演示：停服后改 data/audit/ledger.log 任意帧的 body 字符，再启动
# → 服务以只读降级模式启动；GET /audit/state 显示 ledgerClosed=true、tamperEvidence 与最早受影响序号
# → 新的事件接入、合规清除、到期清除均返回 LEDGER_TAMPERED(503)
#
# 其它破坏手法（均可复现，结论见 GET /audit/state）：
#   删除中间一整行            → MIDDLE_FRAME_MISSING，定位第一个空缺序号
#   删除末尾一行/连续几行     → TAIL_RECORDS_MISSING，定位删后第一个空缺位置
#   交换相邻两行             → REORDERED，定位两条中较小序号
#   把最后一行截断一半（无 intent）→ HALF_FRAME_TAIL
```

> 注意 `server.port=0` 仅用于测试随机端口；手工复现可在命令行加
> `mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8080`。

### 7.3 转发/重投复现

配置 `audit.forward-url` 指向接收端（或测试中的 JDK HttpServer），置 `audit.auto-forward=true`。
接收端依据 `Idempotency-Key` 去重；返回 500/429 可观测指数退避重投，返回 400 观察立即死信。
进程在 INFLIGHT 期间 kill -9，重启后从 `resumePosition()` 继续，不会跳过也不会产生业务重复。

---

## 8. 设计边界与说明

- 威胁模型假设攻击者可改/删账本文件，但**拿不到** `keys/`（hmac.key、DEK、intent/anchor/checkpoint）。
  文件权限尽力设为仅属主；HMAC 密钥泄露后链不再具备防篡改能力——生产环境应把 HMAC 根密钥放入 KMS/HSM。
- 写入意图/锚点/检查点都用 hmac.key 签名：攻击者只改 ledger.log 无法伪造它们，因此“末尾整删/半条/来源不明帧”
  可被检测；反之若攻击者同时拥有 `keys/` 写权限，则可重签锚点绕过该层检测（超出威胁模型）。
- “合规清除”通过删除独立 DEK 实现加密擦除：密文与 envelope 保留可审计，但密码学上不可恢复明文。
  已清除记录的 subject 无法回溯，纯按主体的合规请求不会把它重新纳入；要覆盖这类记录请用序号范围请求。
- 分段核验的检查点默认每 1000 条 DATA 落一个（可用 `new AppendOnlyLedger(path, n)` 调整间隔）；
  段起点必须是检查点边界（或从 1 开始），段内仍逐帧重算 HMAC/CRC，检查点只是“可信起点”，不跳过任何帧验证。
- 转发为 **at-least-once + 接收端幂等 = 有效一次**；接收端必须持久化 `Idempotency-Key` 去重。
- 所有时间/退避逻辑不使用随机抖动，保证测试与行为的确定性。
