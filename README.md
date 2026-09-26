# 防篡改本地审计事件流水线（Tamper-Evident Audit Pipeline）

一个可在本地完整运行的 Spring Boot 服务，实现多来源审计事件的**采集归一化 → 防篡改只追加留存 → 保留/合规清除 → 失败重投转发**全链路，并保证在并发写入、保留仲裁、转发失败与进程重启等场景下结论**一致、可解释、可复现**。

## 1. 它解决什么问题

| 关注点 | 保证 |
|---|---|
| 多来源接入 | 必填校验、类型校验、时间异常分别给出**可区分的拒绝原因**，绝不静默丢弃 |
| 向后兼容 | 可选字段缺失采用确定默认值；未知扩展字段原样保留并参与哈希 |
| 幂等去重 | 稳定幂等键去重；并发同键提交**恰好接受一次**，其余判为重复 |
| 只追加留存 | 哈希链 + 帧 HMAC + 独立锚点；并发下序号**唯一且无空洞** |
| 原子可见 | 长度分帧 + fsync + 锚点原子发布；崩溃后半帧被截断，**半条记录不可见** |
| 篡改检测 | 内容改动 / 删除 / 重排 / 段截断 / 锚点回滚均可检测，定位到**最早受影响序号** |
| 破坏封口 | 检测到破坏后存储进入 **sealed** 状态，明确拒绝一切新追加 |
| 保留仲裁 | 法律保留 &gt; 合规清除 &gt; 保留到期；被保留记录不得清除，阻止项可解释 |
| 可审计清除 | 物理压实重锚哈希链，清除操作写入带 HMAC 的永久凭证 |
| 失败重投 | 按错误类别区分可重试/不可重试；退避重试、死信、显式重放 |
| 重启续投 | outbox 持久化 + 投递租约；重启后从游标位置继续，已投递不重复、未投递不丢失 |

## 2. 模块结构

```
config/     PipelineProperties（audit.* 配置）、PipelineConfig（装配与启动顺序）
domain/     枚举/记录模型/异常、HmacSigner（HMAC-SHA256）、CanonicalJson（确定性序列化）
ingest/     EventNormalizer（归一化/校验）、IdempotencyIndex（幂等索引）、IngestService
storage/    TamperEvidentStore 接口、FileAppendStore（哈希链/锚点/压实）、
            FrameCodec（长度分帧+HMAC）、Anchor、CompactionJournal、CompactionEntry
retention/  LegalHoldStore（法律保留）、RetentionService（优先级仲裁/清除）
forward/    AuditForwarder（Logging/HTTP）、ErrorClassifier、OutboxStore、DeliveryService
web/        AuditController（REST）、GlobalExceptionHandler、ApiDtos
```

## 3. 留存（append-only）与防篡改规则

### 3.1 记录与哈希链
- 每条记录含 `seq`（从 1 开始）、`recordId`（UUID）、归一化事件、`appendedAt`、`prevHash`、`hash`。
- `hash = SHA256(prevHash || canonicalJson(event))`，首条的 `prevHash` 为 64 个 `0`（创世）。
- 规范 JSON（`CanonicalJson`）对对象键按字典序排序、时间统一为 `epoch秒.纳秒`，因此哈希输入与 JVM 的 Map 顺序、Jackson 的时间表示均无关。未知扩展字段在 `event.extensions` 中，**参与哈希**。

### 3.2 分帧与原子可见
段文件 `segment.log` 中每条记录为一个帧：

```
[4 字节大端 payload 长度 N][N 字节记录 JSON][32 字节 HMAC-SHA256(payload)]
```

写入路径（在单把锁内）：
1. 计算新 `seq` 与 `hash`；
2. 追加帧到段文件并 `force(true)`（fsync 数据）；
3. 更新锚点：写 `anchor.json.tmp` → fsync → 原子 rename 为 `anchor.json`。

崩溃恢复（启动时）：
- 只完整解析到**锚点提交长度**为止；
- 尾部不完整长度前缀 / 不完整帧 / 畸形长度一律视为**未确认尾部并截断**，因此**半条记录永远不可见**；
- 帧 HMAC 错误、JSON 损坏、序号非严格升序、前驱哈希不匹配、内容重算哈希不匹配，立即 **sealed** 并给出最早受影响 `seq`。

### 3.3 锚点：防删除/截断/回滚
- `anchor.json` 记录 `{lastSeq, lastHash, length, signature}`，整体经 HMAC 签名，防伪造。
- 段比锚点“短”（记录缺失）、或段长度/链端哈希与锚点不符（可疑尾部）都触发密封。
- `anchor.genesis` 保存进程首见的最高锚点；检测到锚点序号**回滚**（锚点与段被一起倒回更早状态）同样密封。

> 信任边界说明：HMAC 密钥用于阻止“对数据文件有写权限但无密钥”的篡改/伪造。若攻击者同时掌握密钥与全部文件，则可任意伪造；生产环境应通过环境变量 `AUDIT_HMAC_SECRET` 注入受保护的密钥，并把留存目录纳入文件系统权限/审计范围。

### 3.4 封口（seal）语义
完整性破坏在两个时机被处理，均**不会继续写入可疑内容**：

- **启动校验发现破坏（如停服后篡改文件再启动）**：存储初始化抛出 `StorageStateException`，Spring 上下文初始化中止，应用 **fail-fast 拒绝启动**，日志打印 `【留存存储密封】firstAffectedSeq=...`。这保证服务绝不会在“留存完整性未知”的状态下对外提供能力。
- **运行期追加/写入路径发现破坏**：存储进入 `sealed`，记录 `firstAffectedSeq` 与原因，此后 `append` 一律抛 `StorageStateException`；接入层逐条映射为结论 `STORAGE_SEALED`（HTTP 200 批量结果中体现），可通过 `GET /api/audit/health` 查询封口状态。

解除封口属于人工取证处置流程：核对 `compaction-journal.json` 等凭证、定位 `firstAffectedSeq` 后，以受控方式从可信备份恢复，再重启服务。

## 4. 接入归一化规则

| 情况 | 拒绝原因 `RejectReason` |
|---|---|
| 载荷不是 JSON 对象 | `PAYLOAD_NOT_OBJECT` |
| 请求体不是合法 JSON | `MALFORMED_JSON`（HTTP 400，整批拒绝） |
| 缺 `source`/`eventType`/`occurredAt` 或空幂等键 | `MISSING_REQUIRED_FIELD` |
| 字符串字段给了数字/布尔/对象等 | `TYPE_MISMATCH` |
| `occurredAt` 不是可解析 ISO-8601 | `MALFORMED_TIMESTAMP` |
| `occurredAt` 早于 `audit.min-event-time-epoch-seconds` | `TIMESTAMP_TOO_OLD` |
| `occurredAt` 超过当前时间 + `audit.max-future-clock-skew-seconds` | `TIMESTAMP_IN_FUTURE` |
| `retentionDays` 超出 1..36500 | `VALUE_OUT_OF_RANGE` |

- 幂等键：载荷 `idempotencyKey`，或请求头 `X-Idempotency-Key`（载荷优先）。
- 默认语义（确定、向后兼容）：`actorId`、`subject` 缺失归一为空串 `""`；`retentionDays` 缺失取 `audit.default-retention-days`。
- 未识别的顶层字段全部进入 `extensions`（含嵌套对象/数组），原样持久化、参与哈希。
- 幂等索引在启动时从已留存日志重建；运行期 `putIfAbsent` 抢占，占位成功才追加；追加失败释放占位。重复提交返回首次记录，结论为 `DUPLICATE`，不重复写盘。

## 5. 保留、法律保留与合规清除

优先级（从高到低）：

1. **法律保留 legal hold（最高）**：处于保留的记录在任何清除模式下都不得清除，即使保留到期或收到合规清除请求；
2. **合规清除请求**：未被法律保留阻止时按请求清除；
3. **保留到期**：`now >= appendedAt + retentionDays(天)` 且未被法律保留时清除。

两种清除模式：
- `LOGICAL_TOMBSTONE`（默认）：登记墓碑序号，记录字节仍在哈希链上（证据最强、可回溯）；
- `ERASURE`：物理压实——重写临时段、幸存者从创世重新锚定哈希链（`seq`/`recordId` 不变）、原子切换、更新锚点，并把清除凭证写入只增的 `compaction-journal.json`。

清除凭证（HMAC 签名）记录：清除模式、依据（到期/合规请求）、发起人、实际清除序号、**被法律保留阻止的序号**、压实前后的链端哈希。启动时空洞序号必须能在墓碑集合中找到凭证，否则视为未授权删除并密封。压实后仍可正常追加（序号沿用高水位，不产生新的追加空洞）。

## 6. 转发错误分类与重试语义

| 触发 | 分类 | 处理 |
|---|---|---|
| 连接拒绝 / 连接超时 / 读超时 / IO 错误 | `RETRYABLE` | 指数退避重试 |
| HTTP 429、408、5xx | `RETRYABLE` | 指数退避重试 |
| 其余 4xx（400/422 等） | `NON_RETRYABLE` | 立即进入死信 |
| 2xx/3xx | 成功 | 标记 `DELIVERED` |
| 无法识别异常 | 保守按可重试 | 宁可重投，不可丢失 |

- 退避：`min(retryMaxBackoffMs, retryInitialBackoffMs * 2^(attempts-1))`；失败次数达到 `audit.retry-max-attempts` 进入死信。
- **至少一次 + 对端幂等**：成功以“对端 ACK + 本地 DELIVERED 落盘”为准；ACK 后、标记前崩溃会重投一次，HTTP 转发携带 `X-Record-Id`/`X-Record-Seq`，对端应据此幂等。
- **顺序游标**：最靠前的未完成记录阻塞后续；`DELIVERED` 永不重投。
- **投递租约**：领取后置 `IN_FLIGHT` 并设 60 秒租约；进程崩溃重启后租约过期即从**同一序号**继续。
- **死信**：`DEAD_LETTER` 保留不丢，可 `POST /api/audit/delivery/{seq}/replay` 显式重放。
- 默认使用只打日志的本地 sink；配置 `audit.forwarder-url` 后切换为 HTTP 转发。

## 7. 配置项（`application.properties` / 环境变量）

| 键 | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `audit.storage-dir` | `AUDIT_STORAGE_DIR` | `data/audit` | 留存根目录 |
| `audit.hmac-secret` | `AUDIT_HMAC_SECRET` | 本地开发默认值 | 帧/锚点/凭证 HMAC 密钥，生产务必覆盖 |
| `audit.max-future-clock-skew-seconds` | — | `300` | 允许的事件时间未来偏移 |
| `audit.min-event-time-epoch-seconds` | — | `0` | 允许的最早事件时间 |
| `audit.default-retention-days` | — | `90` | 默认保留天数 |
| `audit.legal-hold-precedence` | — | `true` | 法律保留最高优先（恒为真，显式配置） |
| `audit.forwarder-url` | `AUDIT_FORWARDER_URL` | 空（日志 sink） | HTTP 转发目标 |
| `audit.forward-connect-timeout-ms` | — | `2000` | 连接超时 |
| `audit.forward-read-timeout-ms` | — | `5000` | 读取超时 |
| `audit.retry-initial-backoff-ms` | — | `500` | 初始退避 |
| `audit.retry-max-backoff-ms` | — | `30000` | 最大退避 |
| `audit.retry-max-attempts` | — | `5` | 最大尝试次数，之后死信 |
| `audit.retry-on-startup` | — | `true` | 启动自动恢复未完成转发 |

留存目录文件：`segment.log`（帧）、`anchor.json`/`anchor.genesis`（锚点）、`erased-seqs.json`（墓碑）、`legal-hold.json`（法律保留）、`compaction-journal.json`（清除凭证）、`outbox.json`（转发状态）。

## 8. REST 接口

| 方法与路径 | 作用 |
|---|---|
| `POST /api/audit/events` | 接入单对象或数组（可选头 `X-Idempotency-Key`），逐条返回 `outcome/reason/field/message/seq/...` |
| `GET /api/audit/records` / `/{seq}` | 查询留存记录（已清除返回 404） |
| `POST /api/audit/records/{seq}/holds` | 设置法律保留 `{holdId,reason,by}` |
| `DELETE /api/audit/records/{seq}/holds?holdId=` | 解除法律保留 |
| `POST /api/audit/purge/expired` | 保留到期清除，body `{"mode":"LOGICAL_TOMBSTONE"|"ERASURE"}` |
| `POST /api/audit/erase` | 合规清除 `{seqs:[...],requestedBy,mode}` |
| `GET /api/audit/compactions` | 清除凭证列表 |
| `GET /api/audit/delivery` | 全部转发状态 |
| `POST /api/audit/delivery/{seq}/replay` | 死信重放 |
| `GET /api/audit/health` | 密封状态/最早受影响序号/末序号/墓碑/法律保留 |

## 9. 本地验证

要求 JDK 21+、Maven 3.9+。

```bash
# 1) 运行全部测试（23 个，重点为并发追加、篡改、重投、保留边界、字段兼容）
mvn test

# 2) 启动服务（随机本地端口见日志，或自行设置 server.port）
mvn spring-boot:run
```

手动冒烟（另开终端）：

```bash
# 接入（接受）
curl -s -X POST localhost:8080/api/audit/events -H 'Content-Type: application/json' -d '[
 {"idempotencyKey":"e1","source":"billing","eventType":"charge","occurredAt":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'","amount":100},
 {"idempotencyKey":"e1","source":"billing","eventType":"charge","occurredAt":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"},
 {"idempotencyKey":"e2","source":"billing","eventType":"charge","occurredAt":"bad-time"}
]'

# 查询 / 健康 / 转发状态
curl -s localhost:8080/api/audit/records | head -c 500; echo
curl -s localhost:8080/api/audit/health; echo
curl -s localhost:8080/api/audit/delivery; echo

# 法律保留 -> 合规清除被阻止
curl -s -X POST localhost:8080/api/audit/records/1/holds -H 'Content-Type: application/json' \
  -d '{"holdId":"CASE-1","reason":"litigation","by":"officer"}'
curl -s -X POST localhost:8080/api/audit/erase -H 'Content-Type: application/json' \
  -d '{"seqs":[1],"requestedBy":"gdpr","mode":"ERASURE"}'

# 篡改演练：停服 -> 翻转 data/audit/segment.log 中某条帧的一个字节 -> 重启
# 重启后 GET /api/audit/health 将看到 sealed=true 与 firstAffectedSeq，且新事件被拒绝。
```

### 测试与日志可观测性
单测日志会打印每个关键用例的**输入、判定依据与最终状态**（见 `【并发追加】`、`【篡改判定】`、`【密封拒绝】`、`【重试成功】`、`【重启续投】`、`【法律保留-合规清除】` 等前缀），便于复盘“为什么得到该结论”。

- `FileAppendStoreTest`：16 线程 × 50 并发追加的唯一性/无空洞、重启链校验、篡改定位与封口、未授权删除检测、扩展字段保留。
- `CrashRecoveryTest`：尾部半帧截断不产生半记录、段截断与锚点比对检测。
- `IngestConcurrencyTest`：32 线程同键恰好一次、100 异键并发全接受。
- `EventNormalizerTest`：全部拒绝原因可区分 + 默认值 + 扩展保留 + 头幂等键。
- `RetentionServiceTest`：保留 off-by-one 边界、法律保留阻止两类清除、物理压实与清除后重启/追加。
- `DeliveryServiceTest`：错误分类、可重试成功、不可重试立即死信、重试耗尽、死信重放、重启按序续投且不重复不丢失。
- `WebApiIntegrationTest`：HTTP 批量接受/重复/拒绝、坏 JSON 400、缺字段原因、健康状态。

## 10. 设计取舍备注
- 留存采用**单段哈希链 + 锚点**而非数据库，便于零依赖本地复现与逐字节审计；清除通过“压实重锚 + 永久凭证”同时满足被遗忘权与可解释性。
- “无空洞序号”承诺针对**追加阶段**；授权物理清除后允许出现“带清除凭证的空洞”，追加序号仍沿高水位单调递增。
- 转发为至少一次，端到端精确一次依赖下游按 `recordId` 幂等（标准且务实的边界）。
