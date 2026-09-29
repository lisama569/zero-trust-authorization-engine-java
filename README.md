# 零信任授权决策与策略治理引擎（本地可运行）

基于 Spring Boot 3.4 / Java 21 的本地零信任授权引擎。用本地内存状态模拟主体、资源、
环境上下文与策略版本，提供：

- 策略的**加载、校验、发布、回滚**全生命周期治理，非法输入按原因可区分地拒绝；
- 结合**主体角色 + 主体属性附加条件 + 资源类型/敏感级别 + 环境条件**的
  **默认拒绝**授权评估（EQ/NE/IN/NOT_IN/数值比较，缺失与不满足严格区分）；
- **并发评估与版本切换**下的版本一致性（单次评估固定快照，不混用规则）；
- **哈希链审计日志**：关联生效版本、上下文摘要与**实际核对的属性条件**，
  支持**本地文件持久化与重启恢复复核**，篡改/插入/删除/截断可发现，并发不丢记录；
- 调用方请求体与持久化记录中**夹塞未知字段一律拒绝**，绝不静默忽略。

## 1. 构建与本地验证

```bash
# 编译
mvn compile

# 运行全部测试（68 个，单测日志会打印关键输入、版本与判定依据）
mvn test

# 启动服务（默认 8080 端口）
mvn spring-boot:run
```

启动时 `SeedDataInitializer` 会写入演示主体/资源，发布默认策略版本 `1.0.0`，
并登记一个可回滚的属性条件演示版本 `1.1.0`（不改变当前生效版本）。
审计日志默认持久化到 `./data/audit/`（可用配置项覆盖，见 §5）。

### 演示主体与资源

| 主体 | 角色 | 属性 |
|---|---|---|
| alice | engineer | department=platform, employment=full-time |
| bob | auditor | department=security, employment=full-time |
| carol | contractor | department=external, employment=contract |

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
  "policyVersion": "1.0.0",
  "matchedRuleId": "r-allow-auditor-corp",
  "reason": "命中允许规则且无拒绝规则",
  "auditId": "39a8798a-…",
  "evidence": {
    "evaluatedConditions": ["department[EQ]", "employment[NE]"],
    "missingAttributes": []
  }
}
```

`evidence` 给出本判定实际核对的主体属性条件（`属性[比较方式]`）以及缺失的属性键；
不含主体属性的具体值。老版本纯角色规则该列表为空。

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
| `GET /api/audit/verify` | 校验哈希链：`intact / recordCount / brokenAtSequence / detail` |

## 3. 策略模型

```json
{
  "policyVersion": "1.1.0",
  "schemaVersion": "1.0",
  "rules": [
    {
      "id": "r-allow-platform-engineer-secret",
      "name": "平台部全职工程师可读机密文档",
      "effect": "ALLOW",
      "roles": ["engineer"],
      "subjectConditions": [
        {"attribute": "department", "operator": "EQ", "value": "platform"},
        {"attribute": "employment", "operator": "NE", "value": "contract"}
      ],
      "resourceType": "document",
      "maxSensitivity": 5,
      "actions": ["read"],
      "requiredEnvironment": {}
    }
  ]
}
```

规则按以下维度顺序匹配（全部满足才算命中）：

1. **角色**：主体任一角色在规则 `roles` 中；
2. **主体属性附加条件** `subjectConditions`：每个条件都必须成立（详见 §3.3）；
3. **资源类型**：`resourceType` 必须相等；
4. **资源敏感级别**：资源 `sensitivity <= maxSensitivity`（1 最低，5 最高，
   越权访问高敏资源在此被挡住）；
5. **动作**：请求动作在 `actions` 中；
6. **环境条件**：`requiredEnvironment` 中每个键都必须在请求环境中存在且非空；
   值为空串/缺失 => `CONTEXT_MISSING`；值存在但不相等 => 该规则不匹配
   （“信息缺失”与“条件不满足”严格区分，不允许把缺失当作放行或拒绝的借口）。

解析策略：Jackson 开启 `FAIL_ON_UNKNOWN_PROPERTIES`，任何未知字段（含条件对象内）
一律以 `UNKNOWN_FIELD` 拒绝。

### 3.1 主体属性条件模型（subjectConditions）

每条条件形如 `{"attribute": "<主体属性键>", "operator": "<比较方式>", ...}`，
取值字段随比较方式而定：

| operator | 取值字段 | 语义 |
|---|---|---|
| `EQ` | `value` | 属性值等于期望值 |
| `NE` | `value` | 属性值不等于期望值 |
| `IN` | `values`（数组） | 属性值落在取值集合内 |
| `NOT_IN` | `values`（数组） | 属性值不在取值集合内 |
| `GT` / `GTE` / `LT` / `LTE` | `value` | 属性值与期望值按数值比较（>、≥、<、≤），双方都必须可解析为数字 |

三态严格区分，**绝不能因为缺属性就默认放行**：

| 情形 | 单条件结果 | 对规则的影响 |
|---|---|---|
| 属性存在且比较成立 | 命中 | 继续核对下一条件 |
| 属性存在（非空白）但比较不通过，或数值比较时任一侧不是数字 | 不满足 | 该规则 `POLICY_NOT_MATCHED`，**不会**再因别的属性缺失回退成 CONTEXT_MISSING |
| 主体未提供该属性或值为空白 | **缺失** | 该规则记为 `CONTEXT_MISSING`，原因与证据里给出缺失属性键 |

一条规则的所有属性条件都满足，规则才算在属性维度命中。

### 3.2 发布期校验（与属性条件绑定）

属性条件在**发布阶段**就被严格校验，非法策略不会进入版本注册表：

| 失败原因 FailureReason | 触发情形 |
|---|---|
| `UNSUPPORTED_OPERATOR` | `operator` 是引擎不认识的比较方式（如 `REGEX`） |
| `INVALID_CONDITION` | `attribute` 缺失/空白；标量比较缺非空 `value`；`IN/NOT_IN` 缺非空 `values` 或含空元素；数值比较的 `value` 不是数字 |
| `UNKNOWN_FIELD` | 策略或条件对象里夹塞未声明字段 |
| `CONFLICTING_RULES` | 两条规则角色/**属性条件**/资源/动作/环境完全相同却一个 ALLOW 一个 DENY |

### 3.3 评估结论（对外五类，可区分）

| decision | 含义 |
|---|---|
| `ALLOW` | 命中至少一条 ALLOW 规则且未命中任何 DENY |
| `DENY` | 命中显式 DENY 规则（**deny-overrides**，拒绝优先） |
| `CONTEXT_MISSING` | 规则其它维度均满足，但必需环境键缺失（与拒绝区分，便于补全上下文后重试） |
| `POLICY_NOT_MATCHED` | 无规则命中 / 未知主体 / 未知资源 / 请求非法，按默认拒绝处理 |
| `EVALUATION_FAILED` | 引擎内部异常；只返回安全提示，**堆栈不穿透**，审计仍留痕 |

### 3.4 默认拒绝语义

不存在“没有匹配即放行”。无生效策略、未知主体/资源、请求字段缺失、无规则命中，
全部得到非 `ALLOW` 结论。唯一的放行来源是“命中 ALLOW 且没有命中任何 DENY”。

## 4. 版本兼容规则与版本一致性

- `schemaVersion` 采用**主版本兼容**：引擎支持 `1.x`；`2.0` 等其它主版本一律
  以 `INVALID_POLICY` 拒绝。当前支持版本常量见 `PolicyValidator.SUPPORTED_SCHEMA`。
  **主体属性条件是 1.x 内的增量扩展，不提升 schema 主版本**：不含 `subjectConditions`
  的老策略（仅角色 + 资源 + 动作 + 环境）依旧可正常发布、登记与回滚，历史版本
  注册表只增不删，不会因为本次扩展而失效；同一版本号 + 相同输入的评估结论保持稳定。
- `policyVersion` 必填且**不可重复发布**；版本注册表只增不删，任意历史版本均可回滚。
- 回滚目标不存在时返回 `VERSION_NOT_FOUND`，当前版本保持不变。
- 规则级校验：id 非空且不重复、effect 仅允许 ALLOW/DENY、roles/actions/resourceType
  必填、`maxSensitivity` 必须在 1..5、`subjectConditions` 为可选数组但其中每个条件
  都必须通过 §3.2 的发布期校验；两条规则若角色/属性条件/资源/动作/环境完全相同而
  effect 相反，判定为 `CONFLICTING_RULES`，拒绝发布。
- **原子快照切换**：`PolicyVersionManager` 用 `AtomicReference<PublishedPolicy>`
  持有不可变快照；发布/回滚是一次引用切换。`AuthorizationService` 在请求开始时
  读取一次引用并贯穿评估与审计，因此切换进行中的请求只会看到旧版本或新版本的
  完整规则，不会出现跨版本规则混用。同一版本 + 相同输入 => 相同结论。
- **调用方未知字段**：HTTP 层同样开启严格反序列化，评估/治理请求体里出现引擎
  不认识的字段会返回 HTTP 422 与 `UNKNOWN_FIELD`（指明字段名），而不是被静默丢弃后继续算。

## 5. 审计完整性与持久化

每条审计记录包含：序列号、审计 ID、时间戳、主体/动作/资源、资源敏感级、
**关键上下文摘要**（角色集合、资源类型与敏感级、环境键集合；不记录环境敏感值）、
**属性条件依据 `conditionEvidence`**（实际核对了哪些 `属性[比较方式]`、
哪些属性键缺失；不记录主体属性值本身）、判定、命中规则、**实际生效的
policyVersion**、`previousHash` 与 `currentHash`。

```
currentHash = SHA-256( previousHash | 序列号 | 审计ID | 时间戳 | 主体 | 动作
                      | 资源 | 敏感级 | 上下文摘要 | 属性条件依据 | 判定
                      | 规则 | 版本 )
```

- 记录 0 的前驱为固定常量 `GENESIS`，后续每条以前一条 `currentHash` 为前驱，
  形成哈希链。
- `GET /api/audit/verify` 重算全部哈希并检查：序列号连续、前驱指针一致、
  内容哈希一致。任一条被篡改、删除或重排都会返回 `intact=false` 并给出
  `brokenAtSequence`。

### 5.1 本地持久化与重启复核

- 每条记录在返回前以 JSON Lines 追加落盘并 `fsync`，随后更新旁路**检查点文件**
  （记录总数 + 末条 `currentHash`）。路径可配置：

  | 配置项 | 默认值 |
  |---|---|
  | `audit.file.records` | `./data/audit/audit-records.jsonl` |
  | `audit.file.checkpoint` | `./data/audit/audit-checkpoint.json` |

- 应用启动（`AuditLog` Bean 创建）时把历史记录**整体读回**：先逐行严格解析
  （夹带未知字段即拒绝），再与检查点交叉比对，最后重算整条哈希链。复核通过后
  历史记录全部恢复、序列号继续向后分配，`GET /api/audit/verify` 重启后依旧可用。
- **fail-closed**：一旦发现本地记录不可信，启动直接失败，绝不带不可信审计状态继续服务。
- 本地文件被破坏时会指出位置（`AuditPersistenceException.location`）：

  | 破坏方式 | 复核结果 |
  |---|---|
  | 改了某条记录字段 | 末条哈希与检查点不符，或重算到该 `seq` 内容哈希不一致 |
  | 删掉尾部记录（截断） | 实际记录数 < 检查点记录数，报 `after-seq=…` |
  | 删除/插入中间记录 | 行内序列号不连续（`line=…`）或检查点记录数不符 |
  | 插入无法解析 / 夹塞未知字段的伪造行 | 该 `line=…` 解析即失败 |
  | 检查点文件被改坏 | 检查点无法解析或内容不合法 |

- 并发保证：追加在同一把锁内完成“取末条哈希 → 分配序列号 → 入链 → 记录落盘
  → 检查点落盘”，压测 16 线程 × 250 条共 4000 条持久化写入，序列号连续不重复、
  不丢记录、链完整，重启后 4000 条一条不少（内存模式另有 16 × 500 = 8000 条压测）。

## 6. 测试覆盖

| 测试类 | 覆盖内容 |
|---|---|
| `PolicyGovernanceTest` (12) | 发布/回滚、重复版本、非法 JSON、未知字段、非法枚举、缺版本、schema 不兼容、敏感级越界、重复规则 id、ALLOW/DENY 冲突、不存在的回滚目标 |
| `SubjectConditionMatcherTest` (6) | EQ/NE/IN/NOT_IN/GT/GTE/LT/LTE 命中与不命中、数值边界、属性缺失三态、实际值非数字不算缺失 |
| `SubjectConditionPolicyTest` (12) | 属性条件发布期校验：缺 attribute/operator、不支持的 operator、空 value/values、集合含空元素、数值阈值非数字、条件未知字段、同条件 effect 冲突、条件不同不冲突、老格式向后兼容 |
| `SubjectConditionEvaluationTest` (8) | 属性条件全满足 ALLOW、有值不满足默认拒绝、缺属性 CONTEXT_MISSING、数值不达标/非数字、IN 不命中、同版本确定性、审计记录含属性条件依据 |
| `AuthorizationDecisionTest` (11) | ALLOW / 显式 DENY / CONTEXT_MISSING / POLICY_NOT_MATCHED、敏感级权限边界、环境值不匹配 vs 缺失、未知主体/资源/非法输入、同版本确定性、发布与回滚后结论变化 |
| `AuditIntegrityTest` (5) | 正常链、内容篡改、记录缺失、重算哈希伪造、8000 条内存并发追加不丢且链完整 |
| `AuditPersistenceTest` (7) | 重启整体恢复与序列号延续、篡改/截断/删除/插入/未知字段伪造定位、4000 条持久化并发追加不丢且重启后链完整 |
| `UnknownRequestFieldTest` (1) | 评估请求夹塞未知字段 -> 422 UNKNOWN_FIELD 且指出字段名 |
| `ConcurrentSwitchTest` (1) | 8 评估线程 × 400 请求与反复发布/回滚并发，逐条校验“结论 ⇔ 版本”自洽 |
| `WebApiTest` (4) | HTTP 端到端四类结论、UNKNOWN_FIELD/VERSION_NOT_FOUND 返回 422、不泄露堆栈、审计接口字段完整 |
| `ApplicationTests` (1) | Spring 上下文加载 |

所有关键用例均在日志中打印输入、生效版本、命中规则与判定依据（搜索
`授权评估 input` 即可在 surefire 报告中查看）。

## 7. 快速手工验证示例

```bash
# 允许（1.0.0 基线：工程师读中敏感文档）
curl -s -X POST localhost:8080/api/authz/evaluate -H 'Content-Type: application/json' \
  -d '{"subjectId":"alice","action":"read","resourceId":"doc-internal","environment":{}}'

# 上下文缺失
curl -s -X POST localhost:8080/api/authz/evaluate -H 'Content-Type: application/json' \
  -d '{"subjectId":"bob","action":"read","resourceId":"doc-secret","environment":{}}'

# 切到带主体属性条件的演示版本 1.1.0
curl -s -X POST localhost:8080/api/policies/rollback -H 'Content-Type: application/json' \
  -d '{"targetVersion":"1.1.0"}'

# 属性条件全满足：alice 是 platform 部门且非 contract => ALLOW
curl -s -X POST localhost:8080/api/authz/evaluate -H 'Content-Type: application/json' \
  -d '{"subjectId":"alice","action":"read","resourceId":"doc-secret","environment":{}}'

# 属性在但不满足：carol employment=contract（NE contract 不成立）=> POLICY_NOT_MATCHED
curl -s -X POST localhost:8080/api/authz/evaluate -H 'Content-Type: application/json' \
  -d '{"subjectId":"carol","action":"read","resourceId":"doc-secret","environment":{}}'

# 请求夹塞未知字段 => 422 UNKNOWN_FIELD
curl -s -i -X POST localhost:8080/api/authz/evaluate -H 'Content-Type: application/json' \
  -d '{"subjectId":"alice","action":"read","resourceId":"doc-internal","environment":{},"impersonateAdmin":true}'

# 回滚基线版本
curl -s -X POST localhost:8080/api/policies/rollback -H 'Content-Type: application/json' \
  -d '{"targetVersion":"1.0.0"}'

# 回滚到不存在的版本（VERSION_NOT_FOUND, 422）
curl -s -X POST localhost:8080/api/policies/rollback -H 'Content-Type: application/json' \
  -d '{"targetVersion":"nope"}'

# 校验审计链
curl -s localhost:8080/api/audit/verify
```

验证“重启后审计仍可复核”：

```bash
# 1) 打包并把审计文件指到独立目录启动
mvn -DskipTests package
java -jar target/zero-trust-authorization-engine-java-1.0-SNAPSHOT.jar \
  --audit.file.records=/tmp/audit/records.jsonl \
  --audit.file.checkpoint=/tmp/audit/checkpoint.json
# 发若干评估请求后 Ctrl+C 停止

# 2) 用同一路径再次启动，日志可见“审计历史恢复并复核通过，共 N 条记录”，
#    /api/audit/verify 仍为 intact，新写入序列号从 N 继续
java -jar target/zero-trust-authorization-engine-java-1.0-SNAPSHOT.jar \
  --audit.file.records=/tmp/audit/records.jsonl \
  --audit.file.checkpoint=/tmp/audit/checkpoint.json

# 3) 破坏本地文件后启动（如改字段/删尾行/插入伪行），应用 fail-closed 拒绝启动
#    并在日志中给出出问题的位置（line=... / after-seq=... / seq=...）
```

## 8. 主要代码结构

```
model/        领域模型与 Decision/Effect/FailureReason/ConditionOperator 枚举；
              AttributeCondition（属性条件）、MatchEvidence（判定依据）
policy/       PolicyParser（严格解析，含条件 DTO）、PolicyValidator（校验与冲突检测）
version/      PolicyVersionManager（版本注册表 + 原子快照切换）
engine/       PolicyEvaluator（规则匹配与默认拒绝判定）、
              AttributeConditionMatcher（属性条件三态判定）
service/      AuthorizationService（评估门面、异常收口、审计留痕）
              PolicyGovernanceService（治理门面）
audit/        AuditHasher（SHA-256）、AuditLog（并发安全哈希链 + 恢复）、
              AuditStore/FileAuditStore（JSONL 持久化 + 检查点复核）、
              InMemoryAuditStore（测试用）、AuditPersistenceException
directory/    LocalDirectory（本地主体/资源状态）
web/          REST 控制器与全局异常处理
config/       Bean 装配（含审计文件路径与启动恢复）、Jackson 严格模式、种子数据
```
