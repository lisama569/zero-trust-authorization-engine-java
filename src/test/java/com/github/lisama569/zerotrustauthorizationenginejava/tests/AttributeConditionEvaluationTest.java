package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.github.lisama569.zerotrustauthorizationenginejava.model.Decision;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EnvironmentContext;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationResult;
import com.github.lisama569.zerotrustauthorizationenginejava.service.AuthorizationService;
import com.github.lisama569.zerotrustauthorizationenginejava.service.PolicyGovernanceService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 主体属性条件评估测试。
 * 核心不变量：属性缺失（CONTEXT_MISSING）与有值但不满足（POLICY_NOT_MATCHED）
 * 必须可区分，二者都绝不放行；条件全部满足才命中。
 * 审计记录需要体现判定依据了哪些属性条件。
 */
@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AttributeConditionEvaluationTest {

    private static final Logger log = LoggerFactory.getLogger(AttributeConditionEvaluationTest.class);

    @Autowired
    private AuthorizationService authz;
    @Autowired
    private PolicyGovernanceService governance;

    private String version;

    /** 只允许 employment=full-time 且 department IN [platform,security] 的工程师读文档；
     *  clearanceLevel >= 3 的工程师可读机密；缺属性 => CONTEXT_MISSING */
    private String policyJson(String v) {
        return """
                {
                  "policyVersion": "%s",
                  "schemaVersion": "1.1",
                  "rules": [
                    {"id":"attr-allow-normal","name":"全职核心部门工程师读普通文档",
                     "effect":"ALLOW","roles":["engineer"],"resourceType":"document",
                     "maxSensitivity":3,"actions":["read"],"requiredEnvironment":{},
                     "attributeConditions":[
                       {"attribute":"employment","operator":"EQ","value":"full-time"},
                       {"attribute":"department","operator":"IN",
                        "values":["platform","security"]}
                     ]},
                    {"id":"attr-allow-secret","name":"高许可等级工程师读机密",
                     "effect":"ALLOW","roles":["engineer"],"resourceType":"document",
                     "maxSensitivity":5,"actions":["read"],"requiredEnvironment":{},
                     "attributeConditions":[
                       {"attribute":"clearanceLevel","operator":"GTE","value":3}
                     ]}
                  ]
                }
                """.formatted(v);
    }

    @BeforeAll
    void publish() {
        version = "attr-eval-" + UUID.randomUUID();
        governance.publishJson(policyJson(version), "属性条件评估测试");
    }

    @AfterAll
    void restore() {
        governance.rollback("1.0.0");
    }

    private EvaluationRequest req(String subject, String resource) {
        return new EvaluationRequest(subject, "read", resource,
                new EnvironmentContext(Map.of()));
    }

    private EvaluationResult eval(EvaluationRequest r) {
        EvaluationResult result = authz.evaluate(r);
        log.info("属性条件评估 subject={} resource={} -> v={} decision={} rule={} basis='{}'",
                r.getSubjectId(), r.getResourceId(), result.getPolicyVersion(),
                result.getDecision(), result.getMatchedRuleId(), result.getConditionBasis());
        return result;
    }

    @Test
    @DisplayName("alice 全职+platform+clearance4：普通文档与机密均命中 ALLOW")
    void conditionsAllSatisfied() {
        EvaluationResult normal = eval(req("alice", "doc-internal"));
        assertEquals(Decision.ALLOW, normal.getDecision());
        assertEquals("attr-allow-normal", normal.getMatchedRuleId());
        assertEquals(version, normal.getPolicyVersion());
        assertTrue(normal.getConditionBasis().contains("employment EQ full-time"));
        assertTrue(normal.getConditionBasis().contains("满足"));

        EvaluationResult secret = eval(req("alice", "doc-secret"));
        assertEquals(Decision.ALLOW, secret.getDecision());
        assertEquals("attr-allow-secret", secret.getMatchedRuleId());
        assertTrue(secret.getConditionBasis().contains("clearanceLevel GTE 3"));
        assertNotNull(secret.getAuditId());
    }

    @Test
    @DisplayName("同版本相同输入结论稳定（含命中规则与条件依据）")
    void deterministic() {
        EvaluationRequest r = req("alice", "doc-internal");
        EvaluationResult a = eval(r);
        EvaluationResult b = eval(r);
        assertEquals(a.getDecision(), b.getDecision());
        assertEquals(a.getMatchedRuleId(), b.getMatchedRuleId());
        assertEquals(a.getConditionBasis(), b.getConditionBasis());
    }

    @Test
    @DisplayName("属性有值但不满足（carol 是 contract/external）-> 默认拒绝，不是缺失")
    void valueNotSatisfiedIsNotMissing() {
        EvaluationResult r = eval(req("carol", "doc-internal"));
        assertEquals(Decision.POLICY_NOT_MATCHED, r.getDecision());
        assertNull(r.getMatchedRuleId());
        log.info("有值不满足正确区分于缺失：decision={} reason='{}'",
                r.getDecision(), r.getReason());
    }

    @Test
    @DisplayName("数值不满足：clearanceLevel=1 读机密 -> POLICY_NOT_MATCHED")
    void numericNotSatisfied() {
        EvaluationResult r = eval(req("carol", "doc-secret"));
        assertEquals(Decision.POLICY_NOT_MATCHED, r.getDecision());
    }

    @Test
    @DisplayName("主体缺少规则所需属性 -> CONTEXT_MISSING，可与拒绝区分并指明缺失属性")
    void missingAttributeIsContextMissing() {
        EvaluationResult r = evaluateSubjectWithoutAttributes();
        assertEquals(Decision.CONTEXT_MISSING, r.getDecision());
        assertEquals("attr-allow-normal", r.getMatchedRuleId());
        assertTrue(r.getReason().contains("employment"), "原因应指出缺失的属性: " + r.getReason());
        assertTrue(r.getConditionBasis().contains("<missing>"));
        log.info("属性缺失正确识别为 CONTEXT_MISSING：{}", r.getReason());
    }

    @Autowired
    private com.github.lisama569.zerotrustauthorizationenginejava.directory.LocalDirectory directory;

    private EvaluationResult evaluateSubjectWithoutAttributes() {
        directory.putSubject(new com.github.lisama569.zerotrustauthorizationenginejava.model.Subject(
                "dave-noattrs", java.util.List.of("engineer"), Map.of()));
        return eval(req("dave-noattrs", "doc-internal"));
    }
}
