package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.github.lisama569.zerotrustauthorizationenginejava.model.Decision;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EnvironmentContext;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationResult;
import com.github.lisama569.zerotrustauthorizationenginejava.service.AuthorizationService;
import com.github.lisama569.zerotrustauthorizationenginejava.service.PolicyGovernanceService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 授权判定测试：ALLOW/DENY/CONTEXT_MISSING/POLICY_NOT_MATCHED 可区分，
 * 默认拒绝语义、权限边界、版本变更后结论变化且同版本输入结论一致。
 */
@SpringBootTest
class AuthorizationDecisionTest {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationDecisionTest.class);

    @Autowired
    private AuthorizationService authz;
    @Autowired
    private PolicyGovernanceService governance;

    private EvaluationRequest req(String subject, String action, String resource,
                                  Map<String, String> env) {
        return new EvaluationRequest(subject, action, resource,
                new EnvironmentContext(env == null ? Map.of() : env));
    }

    private EvaluationResult evaluateAndLog(EvaluationRequest r) {
        EvaluationResult result = authz.evaluate(r);
        log.info("评估输入 subject={} action={} resource={} env={} -> version={} decision={} rule={} basis='{}'",
                r.getSubjectId(), r.getAction(), r.getResourceId(),
                r.getEnvironment().getAttributes(),
                result.getPolicyVersion(), result.getDecision(),
                result.getMatchedRuleId(), result.getReason());
        return result;
    }

    @Test
    @DisplayName("工程师读取中敏感文档 -> ALLOW")
    void allowEngineerReadInternalDoc() {
        EvaluationResult r = evaluateAndLog(req("alice", "read", "doc-internal", Map.of()));
        assertEquals(Decision.ALLOW, r.getDecision());
        assertEquals("r-allow-engineer-doc", r.getMatchedRuleId());
        assertEquals("1.0.0", r.getPolicyVersion());
        assertNotNull(r.getAuditId());
    }

    @Test
    @DisplayName("工程师读取机密文档超出敏感级边界 -> POLICY_NOT_MATCHED(默认拒绝)")
    void denyBySensitivityBoundary() {
        EvaluationResult r = evaluateAndLog(req("alice", "read", "doc-secret", Map.of()));
        assertEquals(Decision.POLICY_NOT_MATCHED, r.getDecision());
        assertNull(r.getMatchedRuleId());
    }

    @Test
    @DisplayName("外包读机密文档 -> 显式 DENY，可与默认拒绝区分")
    void explicitDenyForContractor() {
        EvaluationResult r = evaluateAndLog(req("carol", "read", "doc-secret", Map.of()));
        assertEquals(Decision.DENY, r.getDecision());
        assertEquals("r-deny-contractor-secret", r.getMatchedRuleId());
    }

    @Test
    @DisplayName("外包写文档无规则 -> POLICY_NOT_MATCHED")
    void contractorNoMatch() {
        EvaluationResult r = evaluateAndLog(req("carol", "write", "doc-internal", Map.of()));
        assertEquals(Decision.POLICY_NOT_MATCHED, r.getDecision());
    }

    @Test
    @DisplayName("审计员在公司网络读机密 -> ALLOW")
    void allowAuditorInCorpNetwork() {
        EvaluationResult r = evaluateAndLog(req("bob", "read", "doc-secret",
                Map.of("networkZone", "corp")));
        assertEquals(Decision.ALLOW, r.getDecision());
        assertEquals("r-allow-auditor-corp", r.getMatchedRuleId());
    }

    @Test
    @DisplayName("审计员缺少环境键 networkZone -> CONTEXT_MISSING，与拒绝可区分")
    void auditorMissingContext() {
        EvaluationResult r = evaluateAndLog(req("bob", "read", "doc-secret", Map.of()));
        assertEquals(Decision.CONTEXT_MISSING, r.getDecision());
        assertEquals("r-allow-auditor-corp", r.getMatchedRuleId());
        assertTrue(r.getReason().contains("networkZone"));
    }

    @Test
    @DisplayName("审计员在非公司网络 -> POLICY_NOT_MATCHED（值不匹配不等于缺失）")
    void auditorWrongNetwork() {
        EvaluationResult r = evaluateAndLog(req("bob", "read", "doc-secret",
                Map.of("networkZone", "vpn")));
        assertEquals(Decision.POLICY_NOT_MATCHED, r.getDecision());
    }

    @Test
    @DisplayName("工程师部署高敏感服务器超出敏感级边界 -> POLICY_NOT_MATCHED（边界优先于环境判断）")
    void deployBlockedBySensitivityBoundary() {
        EvaluationResult r = evaluateAndLog(req("alice", "deploy", "server-prod-1", Map.of()));
        // 服务器敏感级 4 > 规则上限 2 -> 先不匹配，不再评估环境
        assertEquals(Decision.POLICY_NOT_MATCHED, r.getDecision());
    }

    @Test
    @DisplayName("未知主体/未知资源/异常输入默认拒绝且不穿透异常")
    void unknownAndInvalidInputs() {
        assertEquals(Decision.POLICY_NOT_MATCHED,
                evaluateAndLog(req("ghost", "read", "doc-public", Map.of())).getDecision());
        assertEquals(Decision.POLICY_NOT_MATCHED,
                evaluateAndLog(req("alice", "read", "missing-res", Map.of())).getDecision());
        EvaluationResult blank = evaluateAndLog(req("  ", "read", "doc-public", Map.of()));
        assertEquals(Decision.POLICY_NOT_MATCHED, blank.getDecision());
    }

    @Test
    @DisplayName("同版本相同输入结论确定：重复评估完全一致")
    void deterministicSameVersion() {
        EvaluationRequest r = req("alice", "read", "doc-internal", Map.of());
        EvaluationResult a = evaluateAndLog(r);
        EvaluationResult b = evaluateAndLog(r);
        assertEquals(a.getDecision(), b.getDecision());
        assertEquals(a.getMatchedRuleId(), b.getMatchedRuleId());
        assertEquals(a.getPolicyVersion(), b.getPolicyVersion());
    }

    @Test
    @DisplayName("发布新版本改变结论，回滚后结论恢复")
    void versionSwitchAndRollbackChangesDecision() {
        EvaluationRequest r = req("alice", "read", "doc-secret", Map.of());
        Decision before = evaluateAndLog(r).getDecision();
        assertEquals(Decision.POLICY_NOT_MATCHED, before);

        String v2 = """
                {
                  "policyVersion": "2.0.0-decision-test",
                  "schemaVersion": "1.0",
                  "rules": [
                    {"id":"allow-all-docs","name":"工程师可读所有文档","effect":"ALLOW",
                     "roles":["engineer"],"resourceType":"document","maxSensitivity":5,
                     "actions":["read"],"requiredEnvironment":{}}
                  ]
                }
                """;
        governance.publishJson(v2, "放开工程师文档权限");
        EvaluationResult onV2 = evaluateAndLog(r);
        assertEquals(Decision.ALLOW, onV2.getDecision());
        assertEquals("2.0.0-decision-test", onV2.getPolicyVersion());

        governance.rollback("1.0.0");
        EvaluationResult back = evaluateAndLog(r);
        assertEquals(Decision.POLICY_NOT_MATCHED, back.getDecision());
        assertEquals("1.0.0", back.getPolicyVersion());
    }
}
