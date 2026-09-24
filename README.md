# 零信任授权决策与策略治理引擎（本地可运行）

基于 Spring Boot 3.4 / Java 21 的本地零信任授权引擎。使用**本地内存 + 本地文件**
模拟主体、资源、环境上下文与策略版本，无需任何外部依赖即可运行。

核心特性：

- 策略的**加载、校验、发布、回滚**，版本不可变；同版本 + 同输入必然得到相同结论。
- 非法策略、冲突规则、未知字段、不存在的回滚目标**一律显式拒绝**，失败原因可区分。
- 结合**主体属性 + 资源敏感级别 + 环境条件**做**默认拒绝（deny by default）**判断，
  允许 / 拒绝 / 上下文缺失 / 策略不匹配 / 评估失败五种结论对外可区分。
- 策略切换对并发评估原子可见，单次请求**绝不混用两个版本的规则**。
- 追加式**哈希链审计**：记录关联实际生效版本与上下文摘要，可发现篡改与缺失，
  并发压力下不丢记录、无重号、无空洞。

---

## 1. 构建与本地验证

```bash
# 运行全部测试（38 个用例，离线可用）
mvn test

# 启动服务（默认 8080 端口，审计文件 build/audit/audit.log）
mvn spring-boot:run
```

应用启动时会自动注册并发布内置引导策略 `v0-bootstrap`（无条件兜底拒绝），
保证系统在加载业务策略前就处于显式拒绝状态。

### 1.1 快速手工验证

```bash
# 查看当前版本
curl -s http://localhost:8080/api/policies/status

# 加载策略（仅注册，不生效）
curl -s -X POST http://localhost:8080/api/policies/load \
  -H 'Content-Type: application/json' \
  -d '{
    "schemaVersion": 1, "policyId": "root", "version": "v1",
    "rules": [{
      "id": "r-admin", "effect": "ALLOW",
      "conditions": [
        {"source": "SUBJECT", "attribute": "role", "op": "eq", "expected": "admin"},
        {"source": "RESOURCE", "attribute": "sensitivity", "op": "le", "expected": "3"},
        {"source": "ENVIRONMENT", "attribute": "network", "op": "eq", "expected": "corp"}
      ]
    }]
  }'

# 发布 / 回滚
curl -s -X POST http://localhost:8080/api/policies/v1/publish
curl -s -X POST http://localhost:8080/api/policies/v0-bootstrap/rollback

# 授权评估（建议携带 X-Request-Id 便于审计关联）
curl -s -X POST http://localhost:8080/api/authz/evaluate \
  -H 'Content-Type: application/json' -H 'X-Request-Id: demo-1' \
  -d '{
    "subject":  {"id": "u1", "attributes": {"role": "admin"}},
    "resource": {"id": "d1", "attributes": {"sensitivity": "2"}},
    "action": "read",
    "environment": {"attributes": {"network": "corp"}}
  }'

# 审计：查询记录 / 校验哈希链 / 从磁盘重载并校验
curl -s http://localhost:8080/api/audit/records
curl -s http://localhost:8080/api/audit/verify
curl -s -X POST http://localhost:8080/api/audit/reload
```

`examples/` 目录提供可直接使用的样例：

```bash
curl -s -X POST http://localhost:8080/api/policies/load \
  -H 'Content-Type: application/json' --data @examples/policy-v1.json
curl -s -X POST http://localhost:8080/api/policies/v1/publish
curl -s -X POST http://localhost:8080/api/authz/evaluate \
  -H 'Content-Type: application/json' --data @examples/request-allow.json
# 高敏资源即使管理员也会被显式拒绝
curl -s -X POST http://localhost:8080/api/authz/evaluate \
  -H 'Content-Type: application/json' --data @examples/request-deny-high-sensitivity.json
```

审计文件路径可通过 `zt.audit.file` 配置项修改（见 `application.properties`）。

---

## 2. 策略模型

策略 JSON 顶层结构（严格模式，**任何未声明字段都会被拒绝**）：

```json
{
  "schemaVersion": 1,
  "policyId": "root",
  "version": "v1",
  "rules": [
    {
      "id": "r1",
      "effect": "ALLOW",
      "conditions": [
        {"source": "SUBJECT", "attribute": "role", "op": "eq", "expected": "admin"}
      ]
    }
  ]
}
```

| 字段 | 说明 |
|---|---|
| `schemaVersion` | 策略 schema 版本，当前仅支持 `1` |
| `policyId` / `version` | 策略标识与版本号（非空字符串，版本号在版本库内唯一） |
| `rules[].id` | 规则 id，同一策略内不可重复 |
| `rules[].effect` | `ALLOW` 或 `DENY` |
| `conditions[]` | 条件列表；**空列表表示恒匹配**（可用于兜底规则） |

条件 `source` 取值：`SUBJECT` / `RESOURCE` / `ENVIRONMENT`；
`op` 支持：

| 操作符 | 含义 |
|---|---|
| `eq` / `ne` | 字符串相等 / 不等 |
| `in` / `nin` | 值在 / 不在英文逗号分隔的期望集合中 |
| `ge` / `le` | 优先按数值比较，无法解析时退化为字典序 |

### 2.1 求值语义（确定性）

`Evaluator` 是针对单个不可变策略快照的**纯函数**：不读取当前时间、随机数或任何
外部可变状态，因此同一版本 + 同一输入永远得到同一结论（含命中规则与理由文本）。

1. 规则按声明顺序检查；
2. 条件引用的属性键**缺失**时，该规则记为"上下文缺失"并跳过；
3. 条件全部成立则规则命中；
4. 多条命中时**拒绝优先**：只要有一条 DENY 命中，最终就是 DENY；
5. 无任何命中时：有被缺失跳过的规则 → `CONTEXT_MISSING`；否则 `POLICY_NOT_MATCHED`；
6. 评估内部异常 → `EVALUATION_FAILED`，异常堆栈仅写日志，不进入对外响应。

### 2.2 默认拒绝语义（五种结论可区分）

| outcome | 含义 | 是否放行 |
|---|---|---|
| `PERMIT` | 命中至少一条 ALLOW 且没有 DENY 命中 | 放行 |
| `DENY` | 命中 DENY 规则（拒绝优先） | 拒绝 |
| `CONTEXT_MISSING` | 规则需要的上下文字段缺失，无法判定 | 拒绝，调用方补齐上下文后可重试 |
| `POLICY_NOT_MATCHED` | 没有任何规则匹配，按默认拒绝处理 | 拒绝 |
| `EVALUATION_FAILED` | 无已发布策略 / 内部错误，fail-closed | 拒绝 |

系统启动即发布 `v0-bootstrap`（含一条无条件 DENY 规则），保证"无策略不放行"。

---

## 3. 版本兼容规则

- 策略必须显式声明 `schemaVersion`；仅当与引擎支持版本（`1`）**精确相等**时接受，
  否则返回 `SCHEMA_VERSION_INCOMPATIBLE`（422）。不做静默的"向前/向后兼容猜测"。
- 每个 `version` 在版本库中只能注册一次，重复注册返回 `VERSION_ALREADY_EXISTS`。
- 已注册版本是不可变快照，永不原地修改；变更策略 = 注册新版本 + 发布。
- 发布与回滚都是对当前版本引用的**原子替换**（`AtomicReference`）：
  - 评估请求在开始时获取一次当前快照引用，整个请求只使用这一份策略，
    因此切换进行中不会出现"半旧半新"的混合裁决；
  - 回滚目标必须是已注册版本，不存在时返回 `ROLLBACK_TARGET_NOT_FOUND`，
    不允许回滚到一个未知版本。
- 策略加载时先解析、再做语义校验（重复 id / 冲突规则），任一失败都不会进入版本库。

### 3.1 可区分失败原因（`PolicyFailureCode`）

| code | 触发场景 | HTTP |
|---|---|---|
| `MALFORMED_JSON` | JSON 根/字段类型错误、必填项非字符串等 | 422/400 |
| `UNKNOWN_FIELD` | 策略或请求体出现模型未声明字段 | 422/400 |
| `SCHEMA_VERSION_INCOMPATIBLE` | schemaVersion 不受支持 | 422 |
| `MISSING_REQUIRED_FIELD` | 必填字段缺失/空白 | 422 |
| `INVALID_ENUM_VALUE` | effect/source/op 取值非法 | 422 |
| `DUPLICATE_RULE_ID` | 策略内规则 id 重复 | 422 |
| `CONFLICTING_RULES` | 两条规则条件集合相同但效果相反（与条件声明顺序无关） | 422 |
| `VERSION_ALREADY_EXISTS` | 重复注册同一版本号 | 422 |
| `ROLLBACK_TARGET_NOT_FOUND` | 发布/回滚目标版本不存在 | 422 |
| `NO_PUBLISHED_POLICY` | 尚无已发布策略时发起评估 | 结论中体现，fail-closed |

---

## 4. 审计完整性保证

每次授权评估（包括失败与默认拒绝）都会追加一条审计记录，字段包含：
单调序号 `seq`、时间戳、`requestId`、主体/资源/动作、**上下文 SHA-256 摘要**、
**实际生效的策略版本**、结论、命中规则、判定理由、`prevHash`、`recordHash`。

完整性机制：

1. **哈希链**：`recordHash = SHA-256(seq | timestamp | 业务字段 | prevHash)`，
   首条记录前置哈希为固定创世值。修改任意字段（包括 outcome、版本、理由）都会使
   该条哈希不匹配，并导致后续所有记录的链断裂。
2. **防删除/防重排**：校验时要求 seq 从 0 连续递增且每条 `prevHash` 指向上一条，
   删除中间记录、调换顺序都会被发现（重载文件时同样逐行校验）。
3. **上下文绑定**：记录含主体/资源/环境属性排序后的摘要，防止"同结论但换了上下文"
   的静默替换。
4. **并发不丢失**：序号分配、哈希计算、入内存列表、追加写文件在同一把锁内完成；
   磁盘写失败会显式抛错并标记不可写，绝不静默丢记录（`AuditIntegrityTest` 用
   16 线程 × 200 条验证无丢失/无重号/无空洞）。
5. **持久化与重载**：每行一条 JSON 追加到本地文件；启动时自动加载并校验哈希链，
   文件被篡改或截断时启动/重载直接失败暴露问题。

可通过 `GET /api/audit/verify` 在线校验，返回 `intact / recordCount /
firstBrokenSeq / detail`。

---

## 5. REST 接口一览

| 方法与路径 | 说明 |
|---|---|
| `POST /api/policies/load` | 加载并注册策略（严格校验，不自动发布） |
| `POST /api/policies/{version}/publish` | 发布已注册版本 |
| `POST /api/policies/{version}/rollback` | 回滚到已注册版本 |
| `GET  /api/policies/status` | 当前版本与全部已注册版本 |
| `POST /api/authz/evaluate` | 授权评估（可传 `X-Request-Id`） |
| `GET  /api/audit/records` | 查询审计记录 |
| `GET  /api/audit/verify` | 校验哈希链完整性 |
| `POST /api/audit/reload` | 从磁盘重载并校验审计文件 |

所有失败响应统一为 `{"code": "...", "message": "..."}`；未预期内部错误只返回
固定文案 `INTERNAL_ERROR`，细节仅写入服务日志。

---

## 6. 测试覆盖

`mvn test` 运行 38 个用例，日志中打印关键输入、版本与判定依据：

- `EvaluatorTest`：五种结论可区分、拒绝优先、操作符、内部异常不穿透、同版本确定性；
- `PolicyParserValidatorTest`：未知字段（顶层/嵌套）、非法枚举、schema 不兼容、
  缺字段、结构错误、重复规则 id、冲突规则（含条件顺序无关）；
- `PolicyLifecycleTest`：引导默认拒绝、发布、回滚恢复、重复版本、
  回滚/发布目标不存在、非法策略不入库、重复评估一致性；
- `AuthorizationBoundaryTest`：资源敏感级别边界（高敏即拒，压过管理员身份）、
  环境不匹配默认拒绝、上下文缺失；
- `AuditIntegrityTest`：哈希链校验、文件篡改检测、记录缺失检测、
  16 线程并发追加不丢记录；
- `ConcurrentSwitchTest`：12 线程并发评估途中发布新版本，验证结论与版本始终自洽、
  切换前后分别稳定命中旧/新版本、审计无丢失；
- `WebApiIntegrationTest`：端到端 REST 流程与各类可区分错误码。

## 7. 主要代码结构

```
model/          策略/请求/结论/审计记录等值对象
validation/     PolicyParser（严格解析）、PolicyValidator（语义校验）、失败码与异常
versioning/     PolicyStore（版本库+原子快照）、PolicyManagementService（生命周期编排）
engine/         Evaluator（纯函数评估）、AuthorizationService（入口：快照+评估+审计）
audit/          AuditLogger（哈希链、并发追加、持久化、校验）
web/            REST 控制器与 GlobalExceptionHandler
config/         Jackson 严格模式
bootstrap/      v0-bootstrap 默认拒绝策略播种
```
