package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.zerotrustauthorizationenginejava.bootstrap.DefaultPolicySeed;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AccessRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.DecisionOutcome;
import com.github.lisama569.zerotrustauthorizationenginejava.model.DecisionResult;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EnvironmentContext;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Resource;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Subject;
import com.github.lisama569.zerotrustauthorizationenginejava.validation.PolicyFailureCode;
import com.github.lisama569.zerotrustauthorizationenginejava.validation.PolicyValidationException;
import com.github.lisama569.zerotrustauthorizationenginejava.versioning.PolicyManagementService;
import com.github.lisama569.zerotrustauthorizationenginejava.versioning.PolicyStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 策略加载/发布/回滚生命周期测试（完整 Spring 上下文）。 */
@SpringBootTest(properties = "zt.audit.file=build/audit/lifecycle-test.log")
class PolicyLifecycleTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyLifecycleTest.class);

    @Autowired
    private PolicyManagementService managementService;
    @Autowired
    private PolicyStore store;
    @Autowired
    private com.github.lisama569.zerotrustauthorizationenginejava.engine.AuthorizationService authz;
    @Autowired
    private ObjectMapper mapper;

    private JsonNode policyJson(String version, String effect) {
        try {
            return mapper.readTree("""
                    {
                      "schemaVersion": 1,
                      "policyId": "root",
                      "version": "%s",
                      "rules": [
                        {"id": "r-admin", "effect": "%s",
                         "conditions": [
                           {"source": "SUBJECT", "attribute": "role", "op": "eq",
                            "expected": "admin"}]}
                      ]
                    }
                    """.formatted(version, effect));
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    private AccessRequest adminRead() {
        return new AccessRequest(
                new Subject("u1", Map.of("role", "admin")),
                new Resource("d1", Map.of()),
                "read",
                new EnvironmentContext(Map.of()));
    }

    @Test
    void bootstrapPolicyDeniesEverythingByDefault() {
        DecisionResult result = authz.authorize(adminRead(), "life-bootstrap");
        log.info("[引导策略] version={} => {} 依据={}",
                result.version(), result.outcome(), result.reason());
        assertEquals(DefaultPolicySeed.BOOTSTRAP_VERSION, result.version());
        assertEquals(DecisionOutcome.DENY, result.outcome());
    }

    @Test
    void publishThenRollbackRestoresOldConclusion() {
        // 注册 v-allow 与 v-deny 两份业务策略
        managementService.loadAndRegister(policyJson("v-allow-1", "ALLOW"), "test");
        managementService.loadAndRegister(policyJson("v-deny-1", "DENY"), "test");

        managementService.publish("v-allow-1");
        DecisionResult allowed = authz.authorize(adminRead(), "life-allow");
        log.info("[发布 v-allow-1] version={} => {}", allowed.version(), allowed.outcome());
        assertEquals(DecisionOutcome.PERMIT, allowed.outcome());
        assertEquals("v-allow-1", allowed.version());

        managementService.publish("v-deny-1");
        DecisionResult denied = authz.authorize(adminRead(), "life-deny");
        log.info("[发布 v-deny-1] version={} => {}", denied.version(), denied.outcome());
        assertEquals(DecisionOutcome.DENY, denied.outcome());
        assertEquals("v-deny-1", denied.version());

        // 回滚到 v-allow-1，结论必须恢复
        managementService.rollback("v-allow-1");
        DecisionResult rolledBack = authz.authorize(adminRead(), "life-rollback");
        log.info("[回滚 v-allow-1] version={} => {}",
                rolledBack.version(), rolledBack.outcome());
        assertEquals(DecisionOutcome.PERMIT, rolledBack.outcome());
        assertEquals("v-allow-1", rolledBack.version());

        // 最终恢复到引导版本，避免污染同上下文内其他用例的默认状态
        managementService.rollback(DefaultPolicySeed.BOOTSTRAP_VERSION);
    }

    @Test
    void duplicateVersionRegistrationRejected() {
        managementService.loadAndRegister(policyJson("v-dup", "ALLOW"), "test");
        PolicyValidationException ex = assertThrows(PolicyValidationException.class,
                () -> managementService.loadAndRegister(policyJson("v-dup", "ALLOW"),
                        "test-again"));
        log.info("[重复版本] failureCode={}, 细节={}",
                ex.getFailureCode(), ex.getMessage());
        assertEquals(PolicyFailureCode.VERSION_ALREADY_EXISTS, ex.getFailureCode());
    }

    @Test
    void rollbackToUnknownVersionRejected() {
        PolicyValidationException ex = assertThrows(PolicyValidationException.class,
                () -> managementService.rollback("v-does-not-exist"));
        log.info("[回滚目标缺失] failureCode={}, 细节={}",
                ex.getFailureCode(), ex.getMessage());
        assertEquals(PolicyFailureCode.ROLLBACK_TARGET_NOT_FOUND, ex.getFailureCode());
    }

    @Test
    void publishUnknownVersionRejected() {
        PolicyValidationException ex = assertThrows(PolicyValidationException.class,
                () -> managementService.publish("v-never-loaded"));
        log.info("[发布目标缺失] failureCode={}, 细节={}",
                ex.getFailureCode(), ex.getMessage());
        assertEquals(PolicyFailureCode.ROLLBACK_TARGET_NOT_FOUND, ex.getFailureCode());
    }

    @Test
    void invalidPolicyIsRejectedAndNotRegistered() {
        JsonNode invalid = policyJson("v-should-not-register", "WEIRD");
        PolicyValidationException ex = assertThrows(PolicyValidationException.class,
                () -> managementService.loadAndRegister(invalid, "test"));
        assertEquals(PolicyFailureCode.INVALID_ENUM_VALUE, ex.getFailureCode());
        log.info("[非法策略不入库] failureCode={}, 已注册版本包含v-should-not-register={}",
                ex.getFailureCode(), store.versions().contains("v-should-not-register"));
        assertTrue(store.versions().stream().noneMatch("v-should-not-register"::equals));
    }

    @Test
    void sameVersionSameInputProducesSameConclusionAcrossRepeatedCalls() {
        // 用例自包含：注册独立版本（若跨测试重跑已存在则忽略重复注册），再发布。
        try {
            managementService.loadAndRegister(
                    policyJson("v-determinism-life", "ALLOW"), "test");
        } catch (PolicyValidationException alreadyRegistered) {
            assertEquals(PolicyFailureCode.VERSION_ALREADY_EXISTS,
                    alreadyRegistered.getFailureCode());
        }
        managementService.publish("v-determinism-life");
        DecisionResult first = authz.authorize(adminRead(), "life-det-1");
        for (int i = 2; i <= 20; i++) {
            DecisionResult r = authz.authorize(adminRead(), "life-det-" + i);
            assertEquals(first.outcome(), r.outcome());
            assertEquals(first.version(), r.version());
            assertEquals(first.matchedRuleId(), r.matchedRuleId());
        }
        log.info("[生命周期确定性] 20 次重复评估结论一致: {} @ {}",
                first.outcome(), first.version());
        managementService.rollback(DefaultPolicySeed.BOOTSTRAP_VERSION);
    }
}
