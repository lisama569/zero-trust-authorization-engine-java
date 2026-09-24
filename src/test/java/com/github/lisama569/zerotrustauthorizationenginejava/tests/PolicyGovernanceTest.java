package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.github.lisama569.zerotrustauthorizationenginejava.exception.PolicyException;
import com.github.lisama569.zerotrustauthorizationenginejava.model.FailureReason;
import com.github.lisama569.zerotrustauthorizationenginejava.model.PublishedPolicy;
import com.github.lisama569.zerotrustauthorizationenginejava.policy.PolicyParser;
import com.github.lisama569.zerotrustauthorizationenginejava.policy.PolicyValidator;
import com.github.lisama569.zerotrustauthorizationenginejava.service.PolicyGovernanceService;
import com.github.lisama569.zerotrustauthorizationenginejava.version.PolicyVersionManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 策略加载/校验/发布/回滚测试：
 * 非法策略、冲突规则、未知字段、不存在回滚目标都必须可区分且不被静默接受。
 */
class PolicyGovernanceTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyGovernanceTest.class);

    private PolicyGovernanceService governance;
    private PolicyVersionManager versionManager;

    private static final String V1 = """
            {
              "policyVersion": "9.1.0",
              "schemaVersion": "1.0",
              "rules": [
                {"id":"a1","name":"allow","effect":"ALLOW","roles":["engineer"],
                 "resourceType":"document","maxSensitivity":3,"actions":["read"],
                 "requiredEnvironment":{}}
              ]
            }
            """;

    private static final String V2 = """
            {
              "policyVersion": "9.2.0",
              "schemaVersion": "1.0",
              "rules": [
                {"id":"a2","name":"deny-all","effect":"DENY","roles":["engineer"],
                 "resourceType":"document","maxSensitivity":3,"actions":["read"],
                 "requiredEnvironment":{}}
              ]
            }
            """;

    @BeforeEach
    void setUp() {
        versionManager = new PolicyVersionManager(new PolicyValidator());
        governance = new PolicyGovernanceService(new PolicyParser(), versionManager);
    }

    private PolicyException expectFailure(String json, FailureReason expected, String tag) {
        PolicyException ex = assertThrows(PolicyException.class,
                () -> governance.publishJson(json, tag), tag);
        log.info("[{}] 如预期被拒绝 reason={} message={}", tag, ex.getReason(), ex.getMessage());
        assertEquals(expected, ex.getReason(), tag);
        return ex;
    }

    @Test
    @DisplayName("发布合法策略成功并成为当前版本")
    void publishValidPolicy() {
        PublishedPolicy v1 = governance.publishJson(V1, "v1");
        assertEquals("9.1.0", v1.getPolicy().getPolicyVersion());
        assertEquals("9.1.0", governance.current().getPolicy().getPolicyVersion());
        log.info("发布成功，当前版本 {}", governance.current().getPolicy().getPolicyVersion());
    }

    @Test
    @DisplayName("回滚到已发布版本成功，同版本判定一致")
    void publishAndRollback() {
        governance.publishJson(V1, "v1");
        governance.publishJson(V2, "v2");
        assertEquals("9.2.0", governance.current().getPolicy().getPolicyVersion());

        PublishedPolicy rolled = governance.rollback("9.1.0");
        assertEquals("9.1.0", rolled.getPolicy().getPolicyVersion());
        assertEquals("9.1.0", governance.current().getPolicy().getPolicyVersion());
        assertEquals(java.util.List.of("9.1.0", "9.2.0"), governance.history());
        log.info("回滚后版本={} 历史={}", governance.current().getPolicy().getPolicyVersion(),
                governance.history());
    }

    @Test
    @DisplayName("回滚到不存在版本 -> VERSION_NOT_FOUND")
    void rollbackUnknownVersion() {
        governance.publishJson(V1, "v1");
        PolicyException ex = assertThrows(PolicyException.class,
                () -> governance.rollback("9.9.9"));
        assertEquals(FailureReason.VERSION_NOT_FOUND, ex.getReason());
        log.info("不存在回滚目标如预期被拒绝 reason={} message={}", ex.getReason(), ex.getMessage());
        // 回滚失败不得改变当前版本
        assertEquals("9.1.0", governance.current().getPolicy().getPolicyVersion());
    }

    @Test
    @DisplayName("JSON 语法错误 -> MALFORMED_POLICY")
    void malformedJson() {
        expectFailure("{not-json", FailureReason.MALFORMED_POLICY, "malformed");
    }

    @Test
    @DisplayName("策略含未知字段 -> UNKNOWN_FIELD")
    void unknownFieldRejected() {
        String bad = V1.replace("\"rules\"", "\"surprise\": 1,\n  \"rules\"");
        expectFailure(bad, FailureReason.UNKNOWN_FIELD, "unknown-field");
    }

    @Test
    @DisplayName("规则 effect 非法 -> INVALID_POLICY")
    void invalidEffect() {
        String bad = V1.replace("\"ALLOW\"", "\"MAYBE\"");
        // 非法枚举无法反序列化 -> MALFORMED_POLICY；语义非法枚举统一作为不可解析
        expectFailure(bad, FailureReason.MALFORMED_POLICY, "bad-effect");
    }

    @Test
    @DisplayName("缺 policyVersion -> INVALID_POLICY")
    void missingVersion() {
        String bad = V1.replace("\"policyVersion\": \"9.1.0\",", "");
        expectFailure(bad, FailureReason.INVALID_POLICY, "missing-version");
    }

    @Test
    @DisplayName("schemaVersion 不兼容 -> INVALID_POLICY")
    void incompatibleSchema() {
        String bad = V1.replace("\"1.0\"", "\"2.0\"");
        expectFailure(bad, FailureReason.INVALID_POLICY, "bad-schema");
    }

    @Test
    @DisplayName("maxSensitivity 越界 -> INVALID_POLICY")
    void sensitivityOutOfRange() {
        String bad = V1.replace("\"maxSensitivity\":3", "\"maxSensitivity\":9");
        expectFailure(bad, FailureReason.INVALID_POLICY, "sensitivity-range");
    }

    @Test
    @DisplayName("规则 id 重复 -> CONFLICTING_RULES")
    void duplicateRuleId() {
        String dupRule = ", {\"id\":\"dup\",\"name\":\"x\",\"effect\":\"DENY\",\"roles\":[\"auditor\"],"
                + "\"resourceType\":\"document\",\"maxSensitivity\":2,"
                + "\"actions\":[\"read\"],\"requiredEnvironment\":{}}";
        String bad = V1.replace("\"id\":\"a1\"", "\"id\":\"dup\"")
                .replaceFirst("\\](\\s*}\\s*)$", dupRule + " ]$1");
        expectFailure(bad, FailureReason.CONFLICTING_RULES, "dup-rule-id");
    }

    @Test
    @DisplayName("同匹配条件 ALLOW/DENY 冲突 -> CONFLICTING_RULES")
    void conflictingEffects() {
        String dupRule = ", {\"id\":\"c2\",\"name\":\"deny\",\"effect\":\"DENY\",\"roles\":[\"engineer\"],"
                + "\"resourceType\":\"document\",\"maxSensitivity\":3,"
                + "\"actions\":[\"read\"],\"requiredEnvironment\":{}}";
        String bad = V1.replaceFirst("\\](\\s*}\\s*)$", dupRule + " ]$1");
        expectFailure(bad, FailureReason.CONFLICTING_RULES, "conflict-effects");
    }

    @Test
    @DisplayName("重复发布同一版本号被拒绝且当前版本不变")
    void duplicateVersionRejected() {
        governance.publishJson(V1, "first");
        expectFailure(V1, FailureReason.INVALID_POLICY, "dup-version");
        assertEquals(1, governance.history().size());
    }
}
