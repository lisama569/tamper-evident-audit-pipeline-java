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

POST /audit/retention/enforce   ── RetentionService（法律保留 > 到期清除；加密擦除）
POST/DELETE /audit/holds        ── LegalHoldService（法律保留登记/解除）
```

存储目录（默认 `data/audit/`，由 `audit.storage-dir` 配置）：

| 文件 | 内容 |
|---|---|
| `ledger.log` | 逐行 JSON 帧（DATA / PURGE），只追加，哈希链 |
| `keys/<seq>.key` | 每条记录独立的 256 位 DEK；删除该文件即加密擦除 |
| `keys/hmac.key` | 哈希链 HMAC 密钥（位于账本之外，仅属主可读写） |
| `outbox.log` | 转发发件箱事件日志，重放重建状态 |
| `holds.log` | 法律保留 ADD/REMOVE 事件日志 |

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

- 每条 DATA 帧含：`pos`（帧位）、`seq`（数据序号）、幂等键、写入时间、事件时间、密文 `body`、CRC32、`prev`、HMAC `hash`。
- HMAC 输入覆盖序号、幂等键、时间、**密文、CRC** 与前一帧 hash；因此
  **篡改、删除、重排任何一帧都会破坏链**。
- 追加在锁内串行完成，写完 `force(true)` 落盘；数据序号唯一、无空洞。
- **无半条可见**：打开账本时，末尾最后一个没有换行符结尾的物理不完整帧（崩溃撕裂）会被按字节截断后再重放。
- 启动时全量校验；发现破坏时：
  - `firstTamperedSequence` 报告**最早受影响的数据序号**；
  - 账本进入 **closed**；服务以**只读降级模式**保持在线（`GET /audit/state` 可见
    `ledgerClosed=true` 与最早受影响序号），此后所有事件追加与清除操作返回
    `LEDGER_TAMPERED`（HTTP 503），**明确拒绝继续写入或处理可疑内容**。
  - 直接使用 `new AppendOnlyLedger(path)` 的嵌入式用法仍会在打开时抛出 `TamperException`
    （fail-fast）；服务装配走 `openDegraded` 以提供可观测的拒绝响应。
- 未经 PURGE 流程私删 DEK 同样判为篡改（“未授权删除”）。

### 保留与清除（可解释优先级）

`POST /audit/retention/enforce` 以事件 `occurredAtMs`（载荷缺失时回退写入时间）评估，
`cutoff = now - audit.retention-days 天`：

1. **法律保留（最高）**：记录 subject 命中任一 hold 的子串模式 → 保留（`retainedByLegalHold`），无论多旧。
2. **到期清除**：`occurredAt < cutoff` 且未命中 hold → 清除（边界 `== cutoff` 保留，避免临界抖动）。
3. **未到期**：其余保留（`retainedNotExpired`）。

清除方式为**加密擦除**：在哈希链内追加 `PURGE` 标记帧（链本身可审计），随后删除该记录独立 DEK。
此后记录只剩 envelope（序号/幂等键/hash/时间），链仍可验证，明文不可恢复。
崩溃在“标记落盘、DEK 未删”之间时，重启会补删（清除幂等完成）。

法律保留通过 `POST /audit/holds`（`holdId`/`subjectPattern`/`reason`）登记，
`DELETE /audit/holds/{holdId}` 解除；解除后下一轮保留执行即可正常清除。

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
| `GET /audit/state` | 只读状态：账本是否关闭、最早受影响序号、记录数、下一序号、outbox 重投继续位置 |
| `POST /audit/retention/enforce` | 执行保留/清除，返回三类序号清单与策略描述 |
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

关键测试类（共 46 个用例，均打印“输入 / 判定依据 / 最终状态”日志）：

- `EventNormalizerTest`：必填/类型/时间异常分类、默认值、未知字段保留、幂等键稳定
- `AppendOnlyLedgerTest`：无空洞、重放、半帧截断、篡改定位与 closed、私删 DEK、加密擦除
- `ConcurrentAppendTest`：16 线程×100 唯一无空洞；200 并发相同事件恰好 1 落库；300 不同事件全接受
- `RetentionServiceTest`：cutoff ±1 分钟边界、法律保留优先、解除后可清除、清除幂等
- `RetryDispatcherTest`：成功不重复、可重试退避、不可重试死信、次数耗尽、按序与 resumePosition、崩溃 INFLIGHT 回收
- `HttpForwarderTest`：200/408/429/4xx/5xx/连接拒绝/未配置 的错误归类
- `PipelineEndToEndTest`：重启幂等、outbox 补登记、篡改后拒绝新追加、真实 HTTP 成功/500 重投/400 死信
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

# 法律保留 + 清除
curl -s -XPOST localhost:8080/audit/holds -H 'Content-Type: application/json' \
  -d '{"holdId":"h1","subjectPattern":"vip","reason":"诉讼"}'
curl -s -XPOST localhost:8080/audit/retention/enforce

# 篡改演示：停服后改 data/audit/ledger.log 任意帧的 body 字符，再启动
# → 服务以只读降级模式启动；GET /audit/state 显示 ledgerClosed=true 与最早受影响序号
# → 新的事件接入与清除均返回 LEDGER_TAMPERED(503)
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
  HMAC 密钥泄露后链不再具备防篡改能力——生产环境应把 HMAC 根密钥放入 KMS/HSM。
- “合规清除”通过删除独立 DEK 实现加密擦除：密文与 envelope 保留可审计，但密码学上不可恢复明文。
- 转发为 **at-least-once + 接收端幂等 = 有效一次**；接收端必须持久化 `Idempotency-Key` 去重。
- 所有时间/退避逻辑不使用随机抖动，保证测试与行为的确定性。
