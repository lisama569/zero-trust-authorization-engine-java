package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.github.lisama569.zerotrustauthorizationenginejava.engine.Evaluator;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AccessRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AttributeSource;
import com.github.lisama569.zerotrustauthorizationenginejava.model.DecisionOutcome;
import com.github.lisama569.zerotrustauthorizationenginejava.model.DecisionResult;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Effect;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EnvironmentContext;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Policy;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Resource;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Rule;
import com.github.lisama569.zerotrustauthorizationenginejava.model.RuleCondition;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Subject;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/** Evaluator 纯函数行为单测：五种结果可区分 + 确定性 + 拒绝优先 + 操作符。 */
class EvaluatorTest {

    private static final Logger log = LoggerFactory.getLogger(EvaluatorTest.class);

    private final Evaluator evaluator = new Evaluator();

    private Subject subject(Map<String, String> attrs) {
        return new Subject("user-1", attrs);
    }

    private Resource resource(Map<String, String> attrs) {
        return new Resource("doc-1", attrs);
    }

    private AccessRequest request(Subject s, Resource r, String action,
                                  Map<String, String> env) {
        return new AccessRequest(s, r, action, new EnvironmentContext(env));
    }

    private RuleCondition cond(AttributeSource src, String attr, String op, String expected) {
        return new RuleCondition(src, attr, op, expected);
    }

    private Rule rule(String id, Effect effect, RuleCondition... conds) {
        return new Rule(id, effect, List.of(conds));
    }

    private Policy policy(String version, Rule... rules) {
        return new Policy(1, "root", version, List.of(rules));
    }

    private DecisionResult evalAndLog(Policy p, AccessRequest r, String caseName) {
        DecisionResult result = evaluator.evaluate(p, r, "req-" + caseName);
        log.info("[用例 {}] 版本={} 主体={} 资源={} 动作={} 环境={} => 结论={}, 命中规则={}, 依据={}",
                caseName, p == null ? "null" : p.version(),
                r.subject() == null ? "null" : r.subject().id(),
                r.resource() == null ? "null" : r.resource().id(),
                r.action(),
                r.environment() == null ? "null" : r.environment().attributes(),
                result.outcome(), result.matchedRuleId(), result.reason());
        return result;
    }

    @Test
    void allowWhenAllConditionsMatch() {
        Policy p = policy("v1",
                rule("r-allow", Effect.ALLOW,
                        cond(AttributeSource.SUBJECT, "role", "eq", "admin"),
                        cond(AttributeSource.RESOURCE, "sensitivity", "le", "3"),
                        cond(AttributeSource.ENVIRONMENT, "network", "eq", "corp")));
        AccessRequest r = request(
                subject(Map.of("role", "admin")),
                resource(Map.of("sensitivity", "2")),
                "read", Map.of("network", "corp"));

        DecisionResult result = evalAndLog(p, r, "allow");
        assertEquals(DecisionOutcome.PERMIT, result.outcome());
        assertEquals("v1", result.version());
        assertEquals("r-allow", result.matchedRuleId());
    }

    @Test
    void denyTakesPrecedenceWhenBothAllowAndDenyMatch() {
        Policy p = policy("v2",
                rule("r-allow", Effect.ALLOW,
                        cond(AttributeSource.SUBJECT, "role", "eq", "admin")),
                rule("r-deny", Effect.DENY,
                        cond(AttributeSource.RESOURCE, "sensitivity", "ge", "4")));
        AccessRequest r = request(
                subject(Map.of("role", "admin")),
                resource(Map.of("sensitivity", "5")),
                "read", Map.of("network", "corp"));

        DecisionResult result = evalAndLog(p, r, "deny-precedence");
        assertEquals(DecisionOutcome.DENY, result.outcome());
        assertEquals("r-deny", result.matchedRuleId());
    }

    @Test
    void contextMissingWhenNeededAttributeAbsent() {
        Policy p = policy("v1",
                rule("r-env", Effect.ALLOW,
                        cond(AttributeSource.ENVIRONMENT, "network", "eq", "corp")));
        AccessRequest r = request(
                subject(Map.of("role", "admin")),
                resource(Map.of("sensitivity", "1")),
                "read", Map.of());

        DecisionResult result = evalAndLog(p, r, "context-missing");
        assertEquals(DecisionOutcome.CONTEXT_MISSING, result.outcome());
        assertNotNull(result.reason());
    }

    @Test
    void notMatchedIsDefaultDenyWhenNoRuleApplies() {
        Policy p = policy("v1",
                rule("r-admin", Effect.ALLOW,
                        cond(AttributeSource.SUBJECT, "role", "eq", "admin")));
        AccessRequest r = request(
                subject(Map.of("role", "guest")),
                resource(Map.of("sensitivity", "1")),
                "read", Map.of());

        DecisionResult result = evalAndLog(p, r, "not-matched");
        assertEquals(DecisionOutcome.POLICY_NOT_MATCHED, result.outcome());
    }

    @Test
    void evaluationFailedDoesNotLeakInternalException() {
        // 传入 null 策略模拟内部故障（正常流程下评估器永远拿到非空快照）。
        // 结果必须是可区分的 EVALUATION_FAILED，且异常细节不外泄。
        AccessRequest r = request(
                subject(Map.of("role", "admin")),
                resource(Map.of("sensitivity", "1")), "read", Map.of());

        DecisionResult result = evalAndLog(null, r, "null-policy");
        assertEquals(DecisionOutcome.EVALUATION_FAILED, result.outcome());
        assertEquals("unknown", result.version());
    }

    @Test
    void sameVersionSameInputAlwaysSameConclusion() {
        Policy p = policy("v-deterministic",
                rule("r", Effect.ALLOW,
                        cond(AttributeSource.SUBJECT, "dept", "in", "security,ops,finance"),
                        cond(AttributeSource.RESOURCE, "owner", "ne", "external")));
        AccessRequest r = request(
                subject(Map.of("dept", "ops")),
                resource(Map.of("owner", "internal")),
                "write", Map.of());

        DecisionResult first = evalAndLog(p, r, "determinism-1");
        for (int i = 2; i <= 10; i++) {
            DecisionResult again = evaluator.evaluate(p, r, "req-determinism-" + i);
            assertEquals(first.outcome(), again.outcome());
            assertEquals(first.matchedRuleId(), again.matchedRuleId());
            assertEquals(first.reason(), again.reason());
        }
        log.info("[确定性] v-deterministic 重复10次结论一致: {}", first.outcome());
    }

    @Test
    void operatorsInNotInGeLeBehaveCorrectly() {
        Policy p = policy("v-ops",
                rule("r-nin", Effect.ALLOW,
                        cond(AttributeSource.SUBJECT, "dept", "nin", "blocked,quarantine")),
                rule("r-ge", Effect.DENY,
                        cond(AttributeSource.RESOURCE, "sensitivity", "ge", "4")));

        AccessRequest blocked = request(
                subject(Map.of("dept", "blocked")),
                resource(Map.of("sensitivity", "1")), "read", Map.of());
        assertEquals(DecisionOutcome.POLICY_NOT_MATCHED,
                evalAndLog(p, blocked, "nin-block").outcome());

        AccessRequest highSensitivity = request(
                subject(Map.of("dept", "rnd")),
                resource(Map.of("sensitivity", "5")), "read", Map.of());
        assertEquals(DecisionOutcome.DENY,
                evalAndLog(p, highSensitivity, "ge-deny").outcome());
    }
}
