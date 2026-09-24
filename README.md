# 零信任授权决策与策略治理引擎（本地可运行）

基于 Spring Boot 3.4 / Java 21 的本地零信任授权引擎。用本地内存状态模拟主体、资源、
环境上下文与策略版本，提供：

- 策略的**加载、校验、发布、回滚**全生命周期治理，非法输入按原因可区分地拒绝；
- 结合**主体角色/属性 + 资源类型/敏感级别 + 环境条件**的**默认拒绝**授权评估；
- **并发评估与版本切换**下的版本一致性（单次评估固定快照，不混用规则）；
- **哈希链审计日志**：关联生效版本与上下文摘要，篡改/缺失可发现，并发不丢记录。

## 1. 构建与本地验证

```bash
# 编译
mvn compile

# 运行全部测试（34 个，单测日志会打印关键输入、版本与判定依据）
mvn test

# 启动服务（默认 8080 端口）
mvn spring-boot:run
```

启动时 `SeedDataInitializer` 会写入演示主体/资源并发布默认策略版本 `1.0.0`。

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
  "auditId": "39a8798a-…"
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
| `GET /api/audit/records` | 全部审计记录（含序列号、版本、上下文摘要、前后哈希） |
| `GET /api/audit/verify` | 校验哈希链：`intact / recordCount / brokenAtSequence / detail` |

## 3. 策略模型

```json
{
  "policyVersion": "1.0.0",
  "schemaVersion": "1.0",
  "rules": [
    {
      "id": "r-allow-auditor-corp",
      "name": "审计员在公司网络可读任意文档",
      "effect": "ALLOW",
      "roles": ["auditor"],
      "resourceType": "document",
      "maxSensitivity": 5,
      "actions": ["read"],
      "requiredEnvironment": {"networkZone": "corp"}
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
5. **环境条件**：`requiredEnvironment` 中每个键都必须在请求环境中存在且非空；
   值为空串/缺失 => `CONTEXT_MISSING`；值存在但不相等 => 该规则不匹配
   （“信息缺失”与“条件不满足”严格区分，不允许把缺失当作放行或拒绝的借口）。

解析策略：Jackson 开启 `FAIL_ON_UNKNOWN_PROPERTIES`，任何未知字段一律拒绝。

### 3.1 评估结论（对外五类，可区分）

| decision | 含义 |
|---|---|
| `ALLOW` | 命中至少一条 ALLOW 规则且未命中任何 DENY |
| `DENY` | 命中显式 DENY 规则（**deny-overrides**，拒绝优先） |
| `CONTEXT_MISSING` | 规则其它维度均满足，但必需环境键缺失（与拒绝区分，便于补全上下文后重试） |
| `POLICY_NOT_MATCHED` | 无规则命中 / 未知主体 / 未知资源 / 请求非法，按默认拒绝处理 |
| `EVALUATION_FAILED` | 引擎内部异常；只返回安全提示，**堆栈不穿透**，审计仍留痕 |

### 3.2 默认拒绝语义

不存在“没有匹配即放行”。无生效策略、未知主体/资源、请求字段缺失、无规则命中，
全部得到非 `ALLOW` 结论。唯一的放行来源是“命中 ALLOW 且没有命中任何 DENY”。

## 4. 版本兼容规则与版本一致性

- `schemaVersion` 采用**主版本兼容**：引擎支持 `1.x`；`2.0` 等其它主版本一律
  以 `INVALID_POLICY` 拒绝。当前支持版本常量见 `PolicyValidator.SUPPORTED_SCHEMA`。
- `policyVersion` 必填且**不可重复发布**；版本注册表只增不删，任意历史版本均可回滚。
- 回滚目标不存在时返回 `VERSION_NOT_FOUND`，当前版本保持不变。
- 规则级校验：id 非空且不重复、effect 仅允许 ALLOW/DENY、roles/actions/resourceType
  必填、`maxSensitivity` 必须在 1..5；两条规则若匹配维度完全相同而 effect 相反，
  判定为 `CONFLICTING_RULES`，拒绝发布。
- **原子快照切换**：`PolicyVersionManager` 用 `AtomicReference<PublishedPolicy>`
  持有不可变快照；发布/回滚是一次引用切换。`AuthorizationService` 在请求开始时
  读取一次引用并贯穿评估与审计，因此切换进行中的请求只会看到旧版本或新版本的
  完整规则，不会出现跨版本规则混用。同一版本 + 相同输入 => 相同结论。

## 5. 审计完整性保证

每条审计记录包含：序列号、审计 ID、时间戳、主体/动作/资源、资源敏感级、
**关键上下文摘要**（角色集合、资源类型与敏感级、环境键集合；不记录环境敏感值）、
判定、命中规则、**实际生效的 policyVersion**、`previousHash` 与 `currentHash`。

```
currentHash = SHA-256( previousHash | 序列号 | 审计ID | 时间戳 | 主体 | 动作
                      | 资源 | 敏感级 | 上下文摘要 | 判定 | 规则 | 版本 )
```

- 记录 0 的前驱为固定常量 `GENESIS`，后续每条以前一条 `currentHash` 为前驱，
  形成哈希链。
- `GET /api/audit/verify` 重算全部哈希并检查：序列号连续、前驱指针一致、
  内容哈希一致。任一条被篡改、删除或重排都会返回 `intact=false` 并给出
  `brokenAtSequence`（测试 `AuditIntegrityTest` 覆盖三种破坏方式）。
- 并发保证：追加在同一把锁内完成“取末条哈希 → 分配序列号 → 入链”，
  压测 16 线程 × 500 条共 8000 条，序列号连续不重复、不丢记录、链保持完整。

## 6. 测试覆盖

| 测试类 | 覆盖内容 |
|---|---|
| `PolicyGovernanceTest` (12) | 发布/回滚、重复版本、非法 JSON、未知字段、非法枚举、缺版本、schema 不兼容、敏感级越界、重复规则 id、ALLOW/DENY 冲突、不存在的回滚目标 |
| `AuthorizationDecisionTest` (11) | ALLOW / 显式 DENY / CONTEXT_MISSING / POLICY_NOT_MATCHED、敏感级权限边界、环境值不匹配 vs 缺失、未知主体/资源/非法输入、同版本确定性、发布与回滚后结论变化 |
| `AuditIntegrityTest` (5) | 正常链、内容篡改、记录缺失、重算哈希伪造、8000 条并发追加不丢且链完整 |
| `ConcurrentSwitchTest` (1) | 8 评估线程 × 400 请求与反复发布/回滚并发，逐条校验“结论 ⇔ 版本”自洽 |
| `WebApiTest` (4) | HTTP 端到端四类结论、UNKNOWN_FIELD/VERSION_NOT_FOUND 返回 422、不泄露堆栈、审计接口字段完整 |
| `ApplicationTests` (1) | Spring 上下文加载 |

所有关键用例均在日志中打印输入、生效版本、命中规则与判定依据（搜索
`授权评估 input` 即可在 surefire 报告中查看）。

## 7. 快速手工验证示例

```bash
# 允许
curl -s -X POST localhost:8080/api/authz/evaluate -H 'Content-Type: application/json' \
  -d '{"subjectId":"alice","action":"read","resourceId":"doc-internal","environment":{}}'

# 上下文缺失
curl -s -X POST localhost:8080/api/authz/evaluate -H 'Content-Type: application/json' \
  -d '{"subjectId":"bob","action":"read","resourceId":"doc-secret","environment":{}}'

# 回滚到不存在的版本（VERSION_NOT_FOUND, 422）
curl -s -X POST localhost:8080/api/policies/rollback -H 'Content-Type: application/json' \
  -d '{"targetVersion":"nope"}'

# 校验审计链
curl -s localhost:8080/api/audit/verify
```

## 8. 主要代码结构

```
model/        领域模型与 Decision/Effect/FailureReason 枚举
policy/       PolicyParser（严格解析）、PolicyValidator（校验与冲突检测）
version/      PolicyVersionManager（版本注册表 + 原子快照切换）
engine/       PolicyEvaluator（规则匹配与默认拒绝判定）
service/      AuthorizationService（评估门面、异常收口、审计留痕）
              PolicyGovernanceService（治理门面）
audit/        AuditHasher（SHA-256）、AuditLog（并发安全哈希链）
directory/    LocalDirectory（本地主体/资源状态）
web/          REST 控制器与全局异常处理
config/       Bean 装配与种子数据
```
