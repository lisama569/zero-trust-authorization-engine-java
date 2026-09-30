# 零信任授权决策与策略治理引擎（本地可运行）

基于 Spring Boot 3.4 / Java 21 的本地零信任授权引擎。用本地状态模拟主体、资源、
环境上下文与策略版本，提供：

- 策略的**加载、校验、发布、回滚**全生命周期治理，非法输入按原因可区分地拒绝；
- 结合**主体角色/属性 + 资源类型/敏感级别 + 环境条件 + 主体属性条件**
  （相等/不等/集合/数值比较）的**默认拒绝**授权评估，属性“缺失”与“不满足”严格区分；
- **并发评估与版本切换**下的版本一致性（单次评估固定快照，不混用规则）；
- **哈希链审计日志 + 本地 JSONL 持久化 + 带外封签**：关联生效版本、上下文摘要与属性条件依据，
  重启后整体读回继续复核；篡改/插入/删除/截断/**尾部整行删除/历史整体丢失**均可定位，并发不丢记录。

## 1. 构建与本地验证

```bash
# 编译
mvn compile

# 运行全部测试（66 个，单测日志会打印关键输入、版本、判定依据与属性条件）
mvn test

# 启动服务（默认 8080 端口）
mvn spring-boot:run
```

启动时 `SeedDataInitializer` 会写入演示主体/资源，发布默认策略版本 `1.0.0`
（仅角色/资源/环境维度），并登记一份可切换的 `1.1.0`（角色 + 主体属性条件）。
审计文件默认位于 `data/audit-records.jsonl`（旁挂带外封签
`data/audit-records.jsonl.checkpoint.json`），启动时自动重放。

### 演示主体与资源

| 主体 | 角色 | 属性 |
|---|---|---|
| alice | engineer | department=platform, employment=full-time, clearanceLevel=4 |
| bob | auditor | department=security, employment=full-time, clearanceLevel=5 |
| carol | contractor | department=external, employment=contract, clearanceLevel=1 |

| 资源 | 类型 | 敏感级别 |
|---|---|---|
| doc-public | document | 1 |
| doc-internal | document | 3 |
| doc-secret | document | 5 |
| server-prod-1 | server | 4 |

## 2. HTTP 接口

### 2.1 授权评估

`POST /api/authz/evaluate`

```json
{
  "subjectId": "bob",
  "action": "read",
  "resourceId": "doc-secret",
  "environment": {"networkZone": "corp"}
}
```

响应：

```json
{
  "decision": "ALLOW",
  "policyVersion": "1.1.0",
  "matchedRuleId": "r-allow-auditor-security-corp",
  "reason": "命中允许规则且无拒绝规则",
  "auditId": "39a8798a-…",
  "conditionBasis": "department IN [security, compliance] (actual=security, 满足); clearanceLevel GTE 3 (actual=5, 满足)"
}
```

### 2.2 策略治理

| 方法与路径 | 说明 |
|---|---|
| `POST /api/policies/publish` | 体为 `{"note":"…", "policyJson":"<策略 JSON 字符串>"}`，校验通过后发布 |
| `POST /api/policies/rollback` | 体为 `{"targetVersion":"1.0.0"}`，切换到任一历史已发布版本 |
| `GET  /api/policies/current` | 当前生效版本信息 |
| `GET  /api/policies/history` | 已发布版本号列表（按发布顺序） |

治理失败统一返回 HTTP 422 与可区分的 `failureReason`：

```json
{"failureReason": "UNKNOWN_FIELD", "message": "策略包含未知字段: backdoor"}
```

### 2.3 审计

| 方法与路径 | 说明 |
|---|---|
| `GET /api/audit/records` | 全部审计记录（含序列号、版本、上下文摘要、属性条件依据、前后哈希） |
| `GET /api/audit/verify` | 校验哈希链与重启重放：`intact / recordCount / brokenAtSequence / detail / loadedFromPersistence / replayedCount / recoveryDetail / historyLost` |
| `POST /api/audit/recover-history` | 仅在“历史整体丢失”锁定时可用：隔离残留与旧封签（`*.lost-<时间戳>`），重置空历史并重建初始封签；无待恢复状态返回 409 |

## 3. 策略模型

```json
{
  "policyVersion": "1.1.0",
  "schemaVersion": "1.1",
  "rules": [
    {
      "id": "r-allow-auditor-security-corp",
      "name": "安全/合规部门审计员在公司网络可读任意文档",
      "effect": "ALLOW",
      "roles": ["auditor"],
      "resourceType": "document",
      "maxSensitivity": 5,
      "actions": ["read"],
      "requiredEnvironment": {"networkZone": "corp"},
      "attributeConditions": [
        {"attribute": "department", "operator": "IN",
         "values": ["security", "compliance"]},
        {"attribute": "clearanceLevel", "operator": "GTE", "value": 3}
      ]
    }
  ]
}
```

规则按以下维度顺序匹配（全部满足才算命中）：

1. **角色**：主体任一角色在规则 `roles` 中；
2. **资源类型**：`resourceType` 必须相等；
3. **资源敏感级别**：资源 `sensitivity <= maxSensitivity`（1 最低，5 最高，
   越权访问高敏资源在此被挡住）；
4. **动作**：请求动作在 `actions` 中；
5. **主体属性条件**：`attributeConditions` 全部满足（见 3.0）；
6. **环境条件**：`requiredEnvironment` 中每个键都必须在请求环境中存在且非空；
   值为空串/缺失 => `CONTEXT_MISSING`；值存在但不相等 => 该规则不匹配
   （“信息缺失”与“条件不满足”严格区分，不允许把缺失当作放行或拒绝的借口）。

解析策略：Jackson 开启 `FAIL_ON_UNKNOWN_PROPERTIES`，任何未知字段一律拒绝
（策略体、规则、单个条件、以及评估请求体均如此）。

### 3.0 主体属性条件模型 attributeConditions

自 `schemaVersion 1.1` 起，规则可携带可选的 `attributeConditions`。每个条件形如
`{attribute, operator, value|values}`，所有条件是 AND 关系，全满足规则才命中：

| operator | 取值形态 | 语义 |
|---|---|---|
| `EQ` | `value`（标量） | 属性字符串值等于 value |
| `NE` | `value` | 不等于 |
| `IN` | `values`（非空数组） | 属性值落在集合内 |
| `NOT_IN` | `values`（非空数组） | 属性值不在集合内 |
| `GT` / `GTE` / `LT` / `LTE` | `value`（数值） | 按数值大小比较 |

属性值来自本地主体目录 `Subject.attributes`。三种评估结果严格区分、绝不混淆：

- 属性存在且全部条件满足：该条件组通过；
- 属性**存在但值不满足**（含数值比较时任一侧不是数字）：该规则直接 **不匹配**，
  最终走 `POLICY_NOT_MATCHED`（默认拒绝）；
- 属性**未提供或为空白**：该规则记为 `CONTEXT_MISSING`，与“拒绝”分开，
  返回原因里会列出缺失的属性键，便于补全后重试，**不会因缺属性而放行**。
- 同一条规则上若既有“值不满足”又有“属性缺失”，按不匹配处理
  （已有信息足以否定规则）。

发布阶段对条件做可区分的拦截：

| 问题 | failureReason |
|---|---|
| operator 不认识 / 缺失 | `UNSUPPORTED_OPERATOR` |
| value/values 缺失、为空、含空白项，或数值比较 value 非数值，或 attribute 为空 | `INVALID_POLICY` |
| 取值写成对象/数组、value 与 values 同时出现 | `MALFORMED_POLICY` |
| 条件对象里夹带未声明字段 | `UNKNOWN_FIELD` |
| 两条规则角色/资源/动作/环境/**属性条件**完全一致却 effect 相反 | `CONFLICTING_RULES` |

### 3.1 评估结论（对外五类，可区分）

| decision | 含义 |
|---|---|
| `ALLOW` | 命中至少一条 ALLOW 规则且未命中任何 DENY |
| `DENY` | 命中显式 DENY 规则（**deny-overrides**，拒绝优先） |
| `CONTEXT_MISSING` | 规则其它维度均满足，但必需的主体属性或环境键缺失（与拒绝区分，可补全后重试） |
| `POLICY_NOT_MATCHED` | 无规则命中 / 未知主体 / 未知资源 / 请求非法 / 属性值不满足，按默认拒绝处理 |
| `EVALUATION_FAILED` | 引擎内部异常；只返回安全提示，**堆栈不穿透**，审计仍留痕 |

评估响应额外包含 `conditionBasis`，逐条列出决定性规则的属性条件、期望值、
主体实际值及满足情况（只含该规则引用到的属性），便于事后复盘。

### 3.2 默认拒绝语义

不存在“没有匹配即放行”。无生效策略、未知主体/资源、请求字段缺失、无规则命中、
属性值不满足，全部得到非 `ALLOW` 结论。唯一的放行来源是
“命中 ALLOW 且没有命中任何 DENY”。

## 4. 版本兼容规则与版本一致性

- `schemaVersion` 采用**主版本兼容**：引擎支持 `1.x`。老的 `1.0` 策略
  （只有角色/资源/环境、没有 attributeConditions）**照常发布与回滚**，行为不被扩展改变；
  `attributeConditions` 自 1.1 引入且对 1.x 策略可选。`2.0` 等其它主版本一律以
  `INVALID_POLICY` 拒绝。当前支持版本常量见 `PolicyValidator.SUPPORTED_SCHEMA`（1.1）。
- `policyVersion` 必填且**不可重复发布**；版本注册表只增不删，任意历史版本均可回滚。
- 回滚目标不存在时返回 `VERSION_NOT_FOUND`，当前版本保持不变。
- 规则级校验：id 非空且不重复、effect 仅允许 ALLOW/DENY、roles/actions/resourceType
  必填、`maxSensitivity` 必须在 1..5；属性条件按 3.0 校验；两条规则若匹配维度
  （含属性条件）完全相同而 effect 相反，判定为 `CONFLICTING_RULES`，拒绝发布。
- **同版本 + 相同输入 => 相同结论**（含命中规则与条件依据），见
  `AttributeConditionEvaluationTest#deterministic`。
- **原子快照切换**：`PolicyVersionManager` 用 `AtomicReference<PublishedPolicy>`
  持有不可变快照；发布/回滚是一次引用切换。`AuthorizationService` 在请求开始时
  读取一次引用并贯穿评估与审计，因此切换进行中的请求只会看到旧版本或新版本的
  完整规则，不会出现跨版本规则混用。
- **未知输入不放行**：评估请求体中夹带引擎不认识的字段（如 `impersonate`）会被
  全局 Jackson 严格模式拒绝，返回 HTTP 422 + `UNKNOWN_FIELD`，而不是被静默忽略。

## 5. 审计完整性与持久化

每条审计记录包含：序列号、审计 ID、时间戳、主体/动作/资源、资源敏感级、
**关键上下文摘要**（角色集合、主体属性键集合、资源类型与敏感级、环境键集合；
不记录未被规则引用的敏感值）、**属性条件依据 attributeConditionBasis**、
判定、命中规则、**实际生效的 policyVersion**、`previousHash` 与 `currentHash`。

```
currentHash = SHA-256( previousHash | 序列号 | 审计ID | 时间戳 | 主体 | 动作
                      | 资源 | 敏感级 | 上下文摘要 | 判定 | 规则 | 版本
                      | 属性条件依据 )
```

- 记录 0 的前驱为固定常量 `GENESIS`，后续每条以前一条 `currentHash` 为前驱，
  形成哈希链。
- **本地持久化与重启恢复**：记录以 JSONL 逐行追加到
  `audit.file.path`（默认 `data/audit-records.jsonl`；设为 `in-memory` 可关闭）。
  追加在同一把锁内完成“取末条哈希 → 分配序列号 → 强制落盘 → 入内存”，
  已返回给调用方的记录在重启后不会丢。Bean 启动时从文件**整体读回并复核**，
  `GET /api/audit/verify` 的 `loadedFromPersistence` / `replayedCount`
  / `recoveryDetail` 会反映重放与恢复情况。
- **带外封签（checkpoint）**：数据文件旁边还维护
  `data/audit-records.jsonl.checkpoint.json`，记录最近一次已确认落盘的
  **记录条数**与**末条 currentHash**（临时文件 + 原子替换写入，
  且始终“数据先落盘、封签后更新”，崩溃时最多留下“数据多、封签旧”）。
  它独立于数据内容，专门兜住哈希链自检发现不了的两类破坏：
  - **尾部整行删除**：手工把文件末尾一条或连续几条**整行删掉**后，剩下的行
    仍是一条自洽哈希链，只靠链校验会误判完整。重放时拿封签条数/末条哈希比对：
    条数对不上即判 `corrupted=true`，`brokenAtSequence` 给出**缺失起点**
    （= 保留下来的完好前缀长度），`detail` 写明“应有 N 条、实际 M 条、
    seq=M..N-1 被整行删除”。系统把损坏原文件（连同旧封签）重命名为
    `*.corrupt-<时间戳>` 隔离，**只用最长完好前缀重建**，新记录只能接在完好链尾，
    绝不会把残缺部分当成正常历史继续往后追加；
  - **历史整体丢失**：已经产生过记录之后把**整份数据文件删掉/清空**，
    重放读到空历史但封签显示此前有 N 条 → 判 `corrupted=true` 且
    `historyLost=true`，`detail` 给出此前确认条数与末条哈希，报告**无法复核**。
    此时系统**不按“空历史、正常”处理，也不默默从零开始**：追加全部拒绝
    （评估接口返回 HTTP 409 + `AUDIT_HISTORY_UNVERIFIABLE`），直到人工核对后
    调用 `POST /api/audit/recover-history` 显式确认。
    **首次使用**（数据文件与封签都不存在）仍然按空历史正常初始化、可直接追加，
    二者严格区分。
- **显式恢复**：`POST /api/audit/recover-history` 仅在“历史整体丢失”锁定状态下生效：
  残留数据与旧封签被隔离为 `*.lost-<时间戳>` 证据文件，空历史重新建立初始封签，
  新记录从 seq=0 重新计数；无待恢复状态时返回 409。恢复后 `verify` 恢复完整，
  `recoveryDetail` 中保留本次重置说明（仅当次进程可见，证据以隔离文件为准）。
- **本地文件被破坏的发现**：重放从创世起逐条检查序列号连续、前驱指针、内容哈希，
  并识别坏行（截断）与行数不一致。任一条被**改过、插入、中间删除、文件被截断、
  末尾整行删除或末条被替换**，都会返回 `intact=false` 并给出 `brokenAtSequence`；
  除“历史整体丢失”外，可疑原文件被重命名为 `*.corrupt-<时间戳>` 隔离，
  仅用最长完好前缀重建，随后新记录接在完好链尾。
- 并发保证：压测 16 线程 × 500 条内存链共 8000 条、
  12 线程 × 400 条落盘共 4800 条并重启读回，序列号连续不重复、不丢记录、
  链保持完整（`AuditIntegrityTest`、`AuditConcurrentPersistenceTest`）；
  尾部缺失隔离恢复后再 8 线程并发续写 2000 条并重启，序号在完好前缀之上连续不重复
  （`AuditTailLossRecoveryConcurrencyTest`）。

### 审计接口响应（/api/audit/verify）

正常重启：

```json
{
  "intact": true,
  "recordCount": 51,
  "brokenAtSequence": null,
  "detail": "审计链完整",
  "loadedFromPersistence": true,
  "replayedCount": 50,
  "recoveryDetail": "",
  "historyLost": false
}
```

尾部整行删除后重启（示例：原有 10 条，删掉最后 1 条；完好前缀恢复、续写不接残缺）：

```json
{
  "intact": true,
  "recordCount": 9,
  "brokenAtSequence": null,
  "detail": "审计链完整",
  "loadedFromPersistence": true,
  "replayedCount": 9,
  "recoveryDetail": "启动重放时检测到损坏 seq=9：审计记录尾部缺失：封签确认应有 10 条，实际只剩 9 条；自 seq=9 起（含）到 seq=9 的连续记录被整行删除，缺失位置之后不得当作正常历史继续追加；已隔离原文件并恢复 9 条完好记录",
  "historyLost": false
}
```

整份历史文件被删后重启（无法复核、写入锁定；`brokenAtSequence=0`、`recordCount=0`）：

```json
{
  "intact": false,
  "recordCount": 0,
  "brokenAtSequence": 0,
  "detail": "审计历史整体丢失，无法复核（已拒绝追加，需显式恢复）",
  "loadedFromPersistence": true,
  "replayedCount": 0,
  "recoveryDetail": "审计历史整体丢失：带外封签确认此前已有 10 条记录（末条哈希 8f3c…），但数据文件 …/data/audit-records.jsonl 中当前没有任何可解析记录；无法复核，已拒绝追加，需显式恢复后才能重新开始记录",
  "historyLost": true
}
```

## 6. 测试覆盖

| 测试类 | 覆盖内容 |
|---|---|
| `PolicyGovernanceTest` (12) | 发布/回滚、重复版本、非法 JSON、未知字段、非法枚举、缺版本、schema 不兼容、敏感级越界、重复规则 id、ALLOW/DENY 冲突、不存在的回滚目标 |
| `AttributeConditionGovernanceTest` (11) | 八种操作符合法发布、未知/缺失 operator（UNSUPPORTED_OPERATOR）、value 缺失/空白、集合为空/含空项、非数值、缺属性名、非标量、条件未知字段、属性条件参与冲突判定、老 1.0 策略兼容 |
| `AuthorizationDecisionTest` (11) | ALLOW / 显式 DENY / CONTEXT_MISSING / POLICY_NOT_MATCHED、敏感级权限边界、环境值不匹配 vs 缺失、未知主体/资源/非法输入、同版本确定性、发布与回滚后结论变化 |
| `AttributeConditionEvaluationTest` (5) | 属性条件命中、有值不满足 vs 属性缺失严格区分、数值边界、缺属性返回 CONTEXT_MISSING 并指明键名、conditionBasis 内容、同版本确定性 |
| `AuditIntegrityTest` (5) | 正常链、内容篡改、记录缺失、重算哈希伪造、8000 条并发追加不丢且链完整 |
| `AuditPersistenceTest` (11) | 重启整体读回、改写/插入/删除/截断四类文件破坏的定位与隔离恢复；**删末尾 1 条、连续删末尾多条**（封签定位缺失起点与区间、残缺不续写）；**整份历史丢失**（无法复核并锁定、拒绝追加）、**首次使用**正常初始化区分、丢失后**显式恢复**重新计数、封签正常重启不误报 |
| `AuditConcurrentPersistenceTest` (1) | 12×400=4800 条并发落盘后重启全部读回、序列号连续、链完整 |
| `AuditTailLossRecoveryConcurrencyTest` (1) | 尾部删 3 条隔离恢复后 8 线程并发续写 2000 条，序号在完好前缀之上连续不重复，再重启全读回 |
| `ConcurrentSwitchTest` (1) | 8 评估线程 × 400 请求与反复发布/回滚并发，逐条校验“结论 ⇔ 版本”自洽 |
| `WebApiTest` (7) | HTTP 端到端四类结论、属性条件端到端、评估请求未知字段 422、UNKNOWN_FIELD/VERSION_NOT_FOUND 返回 422、不泄露堆栈、审计接口含持久化字段、**历史整体丢失时评估 409 + verify 标记 historyLost + recover-history 恢复** |
| `ApplicationTests` (1) | Spring 上下文加载 |

所有关键用例均在日志中打印输入、生效版本、命中规则、属性条件依据与判定
（搜索 `授权评估 input` 即可在 surefire 报告中查看）。

## 7. 快速手工验证示例

```bash
# 切换到带属性条件的 1.1.0
curl -s -X POST localhost:8080/api/policies/rollback -H 'Content-Type: application/json' \
  -d '{"targetVersion":"1.1.0"}'

# alice(全职/platform/clearance4) 读机密 -> ALLOW，响应含 conditionBasis
curl -s -X POST localhost:8080/api/authz/evaluate -H 'Content-Type: application/json' \
  -d '{"subjectId":"alice","action":"read","resourceId":"doc-secret","environment":{}}'

# carol(contract/external/clearance1) 读机密 -> DENY（非全职）
curl -s -X POST localhost:8080/api/authz/evaluate -H 'Content-Type: application/json' \
  -d '{"subjectId":"carol","action":"read","resourceId":"doc-secret","environment":{}}'

# 回到老 1.0.0：同输入结论恢复为 1.0.0 时代的结果（版本兼容，历史版本不被破坏）
curl -s -X POST localhost:8080/api/policies/rollback -H 'Content-Type: application/json' \
  -d '{"targetVersion":"1.0.0"}'

# 发布不认识的比较方式 -> 422 UNSUPPORTED_OPERATOR
curl -s -X POST localhost:8080/api/policies/publish -H 'Content-Type: application/json' \
  -d '{"policyJson":"{\"policyVersion\":\"x\",\"schemaVersion\":\"1.1\",\"rules\":[{\"id\":\"r\",\"effect\":\"ALLOW\",\"roles\":[\"engineer\"],\"resourceType\":\"document\",\"maxSensitivity\":1,\"actions\":[\"read\"],\"attributeConditions\":[{\"attribute\":\"employment\",\"operator\":\"REGEX\",\"value\":\"x\"}]}]"}'

# 评估请求夹带未知字段 -> 422 UNKNOWN_FIELD
curl -s -X POST localhost:8080/api/authz/evaluate -H 'Content-Type: application/json' \
  -d '{"subjectId":"alice","action":"read","resourceId":"doc-public","environment":{},"impersonate":"admin"}'

# 重启后审计整体读回；手工改 data/audit-records.jsonl 任意一行后重启/再校验，
# 会得到 intact=false 与 brokenAtSequence，原文件被隔离为 *.corrupt-*
curl -s localhost:8080/api/audit/verify
```

### 7.1 尾部删除与历史整体丢失的本地手工验证

先正常跑几轮评估（或直接 `mvn spring-boot:run` 后多调几次 `/api/authz/evaluate`），
让 `data/audit-records.jsonl` 与 `data/audit-records.jsonl.checkpoint.json` 都有内容，
然后停服并分别演练：

```bash
# 场景 A：删掉末尾一整行（或连续几行）后重启
sed -i '$ d' data/audit-records.jsonl          # 删最后 1 条；连删多条可重复执行
mvn spring-boot:run
curl -s localhost:8080/api/audit/verify
# -> intact 反映“已按完好前缀恢复”，recoveryDetail 含：
#    “启动重放时检测到损坏 seq=<缺失起点>：审计记录尾部缺失：封签确认应有 N 条，
#     实际只剩 M 条；自 seq=M 起（含）到 seq=N-1 的连续记录被整行删除…”
# data/ 目录下可看到 audit-records.jsonl.corrupt-<时间戳> 与
# audit-records.jsonl.checkpoint.json.corrupt-<时间戳> 证据文件，
# 新记录只会从 seq=M 接在完好链尾，不会覆盖/假装没发生。

# 场景 B：整份历史文件被删（封签保留）后重启
rm -f data/audit-records.jsonl
mvn spring-boot:run
curl -s localhost:8080/api/audit/verify
# -> {"intact":false,"historyLost":true,"brokenAtSequence":0,"recordCount":0,
#     "detail":"审计历史整体丢失，无法复核（已拒绝追加，需显式恢复）",
#     "recoveryDetail":"审计历史整体丢失：带外封签确认此前已有 N 条记录…"}
# 此时再调评估接口会得到 HTTP 409 + AUDIT_HISTORY_UNVERIFIABLE，系统不写任何新记录。

# 人工核对证据（*.lost-* 尚未产生；数据文件确实缺失）确认接受丢失后，显式恢复：
curl -s -X POST localhost:8080/api/audit/recover-history
# -> {"recovered":true,"historyLost":false,"detail":"历史整体丢失后已显式重置"}
# 残留与旧封签被隔离为 *.lost-<时间戳>，空历史重新建封签，之后记录从 seq=0 开始。

# 对照：首次使用（data/ 下既无数据文件也无封签）直接启动，verify 仍为 intact=true，
# 追加正常，不会误报历史丢失。
```

## 8. 主要代码结构

```
model/        领域模型：AttributeCondition/AttributeOperator、Decision/Effect/FailureReason 等
policy/       PolicyParser（严格解析，含属性条件）、PolicyValidator（取值校验与冲突检测）
version/      PolicyVersionManager（版本注册表 + 原子快照切换）
engine/       PolicyEvaluator（角色/资源/动作/属性条件/环境匹配与默认拒绝判定）
service/      AuthorizationService（评估门面、异常收口、审计留痕）
              PolicyGovernanceService（治理门面）
audit/        AuditHasher（SHA-256）、AuditLog（并发安全哈希链 + 启动重放恢复、
              尾部删除/历史整体丢失判定、丢失锁定与显式恢复）
              AuditStore/FileAuditStore（JSONL 持久化、*.checkpoint.json 带外封签、
              损坏隔离重建、*.lost-* 重置）/InMemoryAuditStore
              AuditHistoryUnavailableException（历史不可复核时拒绝追加）
directory/    LocalDirectory（本地主体/资源状态）
web/          REST 控制器与全局异常处理（未知字段 -> 422 UNKNOWN_FIELD）
config/       Bean 装配（审计文件路径与启动重放）与种子数据（1.0.0 + 1.1.0）
```
