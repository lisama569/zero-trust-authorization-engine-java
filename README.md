# 零信任授权决策与策略治理引擎（本地可运行）

基于 Spring Boot 3.4 / Java 21 的本地零信任授权引擎。用本地状态模拟主体、资源、
环境上下文与策略版本，提供：

- 策略的**加载、校验、发布、回滚**全生命周期治理，非法输入按原因可区分地拒绝；
- 结合**主体角色/属性 + 资源类型/敏感级别 + 环境条件 + 主体属性条件**
  （相等/不等/集合/数值比较）的**默认拒绝**授权评估，属性“缺失”与“不满足”严格区分；
- **并发评估与版本切换**下的版本一致性（单次评估固定快照，不混用规则）；
- **哈希链审计日志 + 本地 JSONL 持久化 + 链外基线**：关联生效版本、上下文
  摘要与属性条件依据，重启后整体读回继续复核；篡改/插入/删除/截断、
  **尾部整段删除**可定位，**历史整体丢失**拒绝续写，并发不丢记录。

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
审计文件默认位于 `data/audit-records.jsonl`（旁路基线为同目录
`audit-records.jsonl.checkpoint`），启动时自动重放。

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
| `GET /api/audit/verify` | 校验哈希链与重启重放：`intact / recordCount / brokenAtSequence / detail / loadedFromPersistence / replayedCount / recoveryDetail` |

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
- **链外基线（checkpoint）**：哈希链只能发现“链上断裂”，无法发现两种
  前缀依然自洽的破坏。因此数据文件旁还维护
  `audit-records.jsonl.checkpoint`（记录上一次已确认的**记录总数**与
  **末条 currentHash**，附防误改校验码，原子替换落盘）。写顺序固定为
  “先 force 落数据，再替换基线”，崩溃窗口至多落后 1 条，重放时凭下链哈希
  自动追赶补齐。基线自首次启动即建立；老版本遗留的无基线数据在链完好时
  自动自举建立基线。
- **尾部整段删除的判定**：手工把文件末尾一条或连续几条记录整行删掉后，
  剩余前缀的哈希链仍然自洽；重放时用基线记录数对比完好前缀，发现条数变少即
  判为**损坏**，`brokenAtSequence` 指向**缺失起点**，`detail` 给出
  “基线应有 N 条 / 实际完好 M 条 / 缺失 N−M 条（自 seq=K 起）”的可定位
  信息。残缺原文件隔离为 `*.corrupt-<时间戳>`，仅恢复完好前缀，**不会把
  残缺部分当正常历史继续往后追加**；恢复后新记录从缺失起点序号续接，
  序号连续不重复。
- **历史整体丢失的判定**：若基线存在且记录数 > 0，但数据文件整体消失，
  判为**不可恢复（unrecoverable）**：`intact=false`、`unrecoverable=true`，
  系统**不**按“空历史、正常”处理，也不自动补建空文件或从零续写——此时任何
  审计追加都抛 `AuditIntegrityException`（经统一收口对外为 500/
  INTERNAL_ERROR，不产生半截历史）。这与**首次使用**（数据文件与基线都不
  存在）严格区分：后者正常初始化，空基线就绪后即可从 seq=0 开始记录。
  运维确认现场后，删除/归档残留基线（与数据文件）再重启，即按首次使用
  重新初始化。
- **其它本地文件破坏的发现**：重放从创世起逐条检查序列号连续、前驱指针、
  内容哈希，并识别坏行（截断）与行数不一致。任一条被**改过、插入、删除中
  间记录或文件被截断**，都会返回损坏并给出 `brokenAtSequence`；可疑原文件
  被重命名隔离，仅用最长完好前缀重建，随后新记录接在完好链尾。
- 并发保证：压测 16 线程 × 500 条内存链共 8000 条、
  12 线程 × 400 条落盘共 4800 条并重启读回，序列号连续不重复、不丢记录、
  链保持完整（`AuditIntegrityTest`、`AuditConcurrentPersistenceTest`）。

### 审计接口响应（/api/audit/verify）

```json
{
  "intact": true,
  "recordCount": 51,
  "brokenAtSequence": null,
  "detail": "审计链完整",
  "loadedFromPersistence": true,
  "replayedCount": 50,
  "recoveryDetail": "",
  "loadCorrupted": false,
  "unrecoverable": false
}
```

字段说明：

| 字段 | 含义 |
|---|---|
| `intact` | 当前内存中的哈希链是否完好；历史整体丢失时恒为 false |
| `brokenAtSequence` | 首个断裂/缺失起点序列号（尾部删除即被删的第一条序号） |
| `detail` | 链校验结论或失败原因 |
| `loadedFromPersistence` / `replayedCount` | 本次启动是否从重放恢复及恢复条数 |
| `loadCorrupted` | 本次启动重放**是否曾检出损坏**（含已自动隔离恢复的尾部删除）；即使恢复后链重新完好，该标记仍为 true，`recoveryDetail` 留有事件说明 |
| `recoveryDetail` | 启动重放时发现的损坏/缺失定位与隔离恢复说明 |
| `unrecoverable` | 历史整体丢失、无法复核且拒绝追加，需运维显式处置 |

## 6. 测试覆盖

| 测试类 | 覆盖内容 |
|---|---|
| `PolicyGovernanceTest` (12) | 发布/回滚、重复版本、非法 JSON、未知字段、非法枚举、缺版本、schema 不兼容、敏感级越界、重复规则 id、ALLOW/DENY 冲突、不存在的回滚目标 |
| `AttributeConditionGovernanceTest` (11) | 八种操作符合法发布、未知/缺失 operator（UNSUPPORTED_OPERATOR）、value 缺失/空白、集合为空/含空项、非数值、缺属性名、非标量、条件未知字段、属性条件参与冲突判定、老 1.0 策略兼容 |
| `AuthorizationDecisionTest` (11) | ALLOW / 显式 DENY / CONTEXT_MISSING / POLICY_NOT_MATCHED、敏感级权限边界、环境值不匹配 vs 缺失、未知主体/资源/非法输入、同版本确定性、发布与回滚后结论变化 |
| `AttributeConditionEvaluationTest` (5) | 属性条件命中、有值不满足 vs 属性缺失严格区分、数值边界、缺属性返回 CONTEXT_MISSING 并指明键名、conditionBasis 内容、同版本确定性 |
| `AuditIntegrityTest` (5) | 正常链、内容篡改、记录缺失、重算哈希伪造、8000 条并发追加不丢且链完整 |
| `AuditPersistenceTest` (13) | 重启整体读回、改写/插入/删除/截断四类文件破坏的定位与隔离恢复、**尾部删 1 条与连续删多条的定位及恢复后续写**、**整份历史丢失不可恢复且拒绝追加/首次使用正常初始化/显式处置后重置**、多轮正常重启序号连续、崩溃窗口基线追赶、超窗领先判损坏、老数据无基线自举 |
| `AuditConcurrentPersistenceTest` (1) | 12×400=4800 条并发落盘后重启全部读回、序列号连续、链完整 |
| `ConcurrentSwitchTest` (1) | 8 评估线程 × 400 请求与反复发布/回滚并发，逐条校验“结论 ⇔ 版本”自洽 |
| `WebApiTest` (6) | HTTP 端到端四类结论、属性条件端到端、评估请求未知字段 422、UNKNOWN_FIELD/VERSION_NOT_FOUND 返回 422、不泄露堆栈、审计接口含持久化字段 |
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

# —— 尾部整段删除验证 ——
# 先产生若干条记录，然后停服，删掉 JSONL 末尾一整行（或连续几行）后重启：
sed -i '$d' data/audit-records.jsonl          # 删最后一条；连续删多条可重复执行
# 重启后再校验：loadCorrupted=true，recoveryDetail 含“检测到尾部记录缺失：
# 基线记录应有 N 条，实际完好 M 条，缺失 K 条（尾部缺失自 seq=K 起）”，
# 原文件被隔离为 *.corrupt-*，内存仅保留 M 条完好前缀；此后新追加的记录从
# seq=M 续接，再重启恢复正常（loadCorrupted 回到 false）。
curl -s localhost:8080/api/audit/verify

# —— 历史整体丢失验证 ——
# 停服后只保留基线、删掉整份数据文件（注意不要删 .checkpoint）：
rm data/audit-records.jsonl
# 重启后校验：intact=false、unrecoverable=true、loadCorrupted=true，
# detail 说明“基线记录应有 N 条，但数据文件不存在”；评估/追加被拒绝
# （返回 500 INTERNAL_ERROR），系统不会默默从 seq=0 重新开始。
curl -s localhost:8080/api/audit/verify
# 运维确认后显式处置：归档/删除残留基线（数据文件本就不存在），重启即按
# 首次使用重新初始化（空历史、空基线，可正常从 seq=0 记录）。
rm -f data/audit-records.jsonl.checkpoint
```

## 8. 主要代码结构

```
model/        领域模型：AttributeCondition/AttributeOperator、Decision/Effect/FailureReason 等
policy/       PolicyParser（严格解析，含属性条件）、PolicyValidator（取值校验与冲突检测）
version/      PolicyVersionManager（版本注册表 + 原子快照切换）
engine/       PolicyEvaluator（角色/资源/动作/属性条件/环境匹配与默认拒绝判定）
service/      AuthorizationService（评估门面、异常收口、审计留痕）
              PolicyGovernanceService（治理门面）
audit/        AuditHasher（SHA-256）、AuditLog（并发安全哈希链 + 启动重放恢复
              + 尾部删除/整体丢失判定）
              AuditCheckpoint（链外基线：记录数 + 末条哈希 + 校验码）
              AuditStore/FileAuditStore（JSONL 持久化、基线、损坏隔离重建）
              /InMemoryAuditStore、AuditIntegrityException（不可恢复时拒绝追加）
directory/    LocalDirectory（本地主体/资源状态）
web/          REST 控制器与全局异常处理（未知字段 -> 422 UNKNOWN_FIELD）
config/       Bean 装配（审计文件路径与启动重放）与种子数据（1.0.0 + 1.1.0）
```
