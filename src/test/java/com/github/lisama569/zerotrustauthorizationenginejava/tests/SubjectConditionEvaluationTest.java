package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLog;
import com.github.lisama569.zerotrustauthorizationenginejava.directory.LocalDirectory;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Decision;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EnvironmentContext;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationResult;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Subject;
import com.github.lisama569.zerotrustauthorizationenginejava.service.AuthorizationService;
import com.github.lisama569.zerotrustauthorizationenginejava.service.PolicyGovernanceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 属性条件端到端判定测试：
 * 全部条件命中才 ALLOW；属性在但不满足 -> 默认拒绝；属性缺失 -> CONTEXT_MISSING；
 * 同版本同输入结论稳定；审计记录体现判定依据的属性条件。
 */
@SpringBootTest
class SubjectConditionEvaluationTest {

    private static final Logger log = LoggerFactory.getLogger(SubjectConditionEvaluationTest.class);

    @Autowired
    private AuthorizationService authz;
    @Autowired
    private PolicyGovernanceService governance;
    @Autowired
    private AuditLog auditLog;
    @Autowired
    private LocalDirectory directory;

    /**
     * Spring 上下文在测试类间共享，其它测试可能发布/切换过版本。
     * 每个用例开始前统一回到种子版本 1.0.0（纯角色/资源基线），保证前提确定；
     * 需要属性条件种子规则的用例自行回滚到 1.1.0。
     */
    @BeforeEach
    void resetToSeedVersion() {
        governance.rollback("1.0.0");
    }

    private EvaluationRequest req(String subject, String action, String resource,
                                  Map<String, String> env) {
        return new EvaluationRequest(subject, action, resource,
                new EnvironmentContext(env == null ? Map.of() : env));
    }

    private EvaluationResult eval(EvaluationRequest r) {
        EvaluationResult result = authz.evaluate(r);
        log.info("属性条件评估 subject={} resource={} -> version={} decision={} rule={} evidence={}",
                r.getSubjectId(), r.getResourceId(), result.getPolicyVersion(),
                result.getDecision(), result.getMatchedRuleId(),
                result.getEvidence() == null ? null
                        : "evaluated=" + result.getEvidence().getEvaluatedConditions()
                          + ",missing=" + result.getEvidence().getMissingAttributes());
        return result;
    }

    private String gte3Policy(String version) {
        return """
                {
                  "policyVersion": "%s",
                  "schemaVersion": "1.0",
                  "rules": [
                    {"id":"cond-clearance","name":"密级达标可读机密","effect":"ALLOW",
                     "roles":["engineer"],
                     "subjectConditions":[{"attribute":"clearanceLevel","operator":"GTE","value":"3"}],
                     "resourceType":"document","maxSensitivity":5,"actions":["read"],
                     "requiredEnvironment":{}}
                  ]
                }
                """.formatted(version);
    }

    @Test
    @DisplayName("种子1.1.0：alice 平台部+全职，两条属性条件全满足 -> ALLOW")
    void allConditionsSatisfiedAllow() {
        governance.rollback("1.1.0");
        EvaluationResult r = eval(req("alice", "read", "doc-secret", Map.of()));
        assertEquals(Decision.ALLOW, r.getDecision());
        assertEquals("r-allow-platform-engineer-secret", r.getMatchedRuleId());
        assertNotNull(r.getEvidence());
        assertTrue(r.getEvidence().getEvaluatedConditions().contains("department[EQ]"));
        assertTrue(r.getEvidence().getEvaluatedConditions().contains("employment[NE]"));
    }

    @Test
    @DisplayName("carol 外包 employment=contract，NE contract 不满足 -> 非 CONTEXT_MISSING，默认拒绝")
    void conditionNotSatisfiedIsNotMissing() {
        governance.rollback("1.1.0");
        EvaluationResult r = eval(req("carol", "read", "doc-secret", Map.of()));
        assertNotEquals(Decision.CONTEXT_MISSING, r.getDecision(),
                "属性在但不满足，不能报缺失");
        log.info("carol 条件不满足结论={} rule={}", r.getDecision(), r.getMatchedRuleId());
    }

    @Test
    @DisplayName("有角色但属性未提供 -> CONTEXT_MISSING，原因指出缺失属性键")
    void missingAttributeYieldsContextMissing() {
        String version = "3.0.0-cond-missing-" + UUID.randomUUID();
        governance.publishJson(gte3Policy(version), "密级条件缺失测试");

        // engineer 角色，但属性表里根本没有 clearanceLevel
        String subjectId = "eng-no-clearance-" + UUID.randomUUID();
        directory.putSubject(new Subject(subjectId, List.of("engineer"), Map.of()));

        EvaluationResult r = eval(req(subjectId, "read", "doc-secret", Map.of()));
        assertEquals(Decision.CONTEXT_MISSING, r.getDecision(), "属性未提供必须区别于拒绝");
        assertEquals("cond-clearance", r.getMatchedRuleId());
        assertTrue(r.getReason().contains("clearanceLevel"));
        assertNotNull(r.getEvidence());
        assertTrue(r.getEvidence().getMissingAttributes().contains("clearanceLevel"));
    }

    @Test
    @DisplayName("属性在但数值不达标 -> POLICY_NOT_MATCHED（不能当作缺失放行）")
    void presentButBelowThreshold() {
        String version = "3.0.1-cond-low-" + UUID.randomUUID();
        governance.publishJson(gte3Policy(version), "密级不达标测试");

        String subjectId = "eng-low-clearance-" + UUID.randomUUID();
        directory.putSubject(new Subject(subjectId, List.of("engineer"),
                Map.of("clearanceLevel", "1")));

        EvaluationResult r = eval(req(subjectId, "read", "doc-secret", Map.of()));
        assertEquals(Decision.POLICY_NOT_MATCHED, r.getDecision());
        assertNull(r.getMatchedRuleId());
    }

    @Test
    @DisplayName("属性值非数字 -> 有值但不满足，POLICY_NOT_MATCHED")
    void nonNumericAttributeValue() {
        String version = "3.0.2-cond-nan-" + UUID.randomUUID();
        governance.publishJson(gte3Policy(version), "密级非数值测试");

        String subjectId = "eng-nan-" + UUID.randomUUID();
        directory.putSubject(new Subject(subjectId, List.of("engineer"),
                Map.of("clearanceLevel", "topsecret")));

        EvaluationResult r = eval(req(subjectId, "read", "doc-secret", Map.of()));
        assertEquals(Decision.POLICY_NOT_MATCHED, r.getDecision());
    }

    @Test
    @DisplayName("IN 条件：部门不在取值集合 -> 默认拒绝（属性在、不满足）")
    void inCondition() {
        String denyVersion = "3.1.0-in-" + UUID.randomUUID();
        String json = """
                {
                  "policyVersion": "%s",
                  "schemaVersion": "1.0",
                  "rules": [
                    {"id":"cond-in","name":"仅平台部门","effect":"ALLOW","roles":["auditor"],
                     "subjectConditions":[{"attribute":"department","operator":"IN",
                       "values":["platform"]}],
                     "resourceType":"document","maxSensitivity":5,"actions":["read"],
                     "requiredEnvironment":{}}
                  ]
                }
                """.formatted(denyVersion);
        governance.publishJson(json, "IN 条件");

        EvaluationResult r = eval(req("bob", "read", "doc-secret", Map.of()));
        assertEquals(Decision.POLICY_NOT_MATCHED, r.getDecision());
    }

    @Test
    @DisplayName("同版本相同输入结论稳定（含属性条件）")
    void deterministicWithConditions() {
        governance.rollback("1.1.0");
        EvaluationRequest r = req("alice", "read", "doc-secret", Map.of());
        EvaluationResult a = eval(r);
        EvaluationResult b = eval(r);
        assertEquals(a.getDecision(), b.getDecision());
        assertEquals(a.getMatchedRuleId(), b.getMatchedRuleId());
        assertEquals(a.getPolicyVersion(), b.getPolicyVersion());
    }

    @Test
    @DisplayName("审计记录体现命中所依据的属性条件")
    void auditRecordContainsConditionEvidence() {
        governance.rollback("1.1.0");
        eval(req("alice", "read", "doc-secret", Map.of()));
        AuditRecord last = auditLog.all().get(auditLog.size() - 1);
        assertNotNull(last.getConditionEvidence(), "审计记录必须包含属性条件依据");
        assertTrue(last.getConditionEvidence().contains("department[EQ]"));
        assertTrue(last.getConditionEvidence().contains("employment[NE]"));
        log.info("审计条件依据: {}", last.getConditionEvidence());
    }
}
