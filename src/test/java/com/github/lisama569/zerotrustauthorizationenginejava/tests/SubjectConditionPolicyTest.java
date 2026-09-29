package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.github.lisama569.zerotrustauthorizationenginejava.exception.PolicyException;
import com.github.lisama569.zerotrustauthorizationenginejava.model.FailureReason;
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
 * 属性条件发布期校验测试：
 * 非法写法 / 不支持的比较方式 / 取值不合理 / 条件相同 effect 冲突，
 * 都必须在发布阶段被挡下且原因可区分；老策略（无 subjectConditions）照常发布。
 */
class SubjectConditionPolicyTest {

    private static final Logger log = LoggerFactory.getLogger(SubjectConditionPolicyTest.class);

    private PolicyGovernanceService governance;

    private static final String BASE_TEMPLATE = """
            {
              "policyVersion": "%s",
              "schemaVersion": "1.0",
              "rules": [
                {"id":"r1","name":"带属性条件的规则","effect":"ALLOW","roles":["engineer"],
                 "resourceType":"document","maxSensitivity":3,"actions":["read"],
                 "requiredEnvironment":{},
                 "subjectConditions": %s
                }
              ]
            }
            """;

    @BeforeEach
    void setUp() {
        PolicyVersionManager versionManager = new PolicyVersionManager(new PolicyValidator());
        governance = new PolicyGovernanceService(new PolicyParser(), versionManager);
    }

    private String policy(String version, String conditions) {
        return BASE_TEMPLATE.formatted(version, conditions);
    }

    private void expectFailure(String json, FailureReason expected, String tag) {
        PolicyException ex = assertThrows(PolicyException.class,
                () -> governance.publishJson(json, tag), tag);
        assertEquals(expected, ex.getReason(), tag);
        log.info("[{}] 如预期被拒绝 reason={} message={}", tag, ex.getReason(), ex.getMessage());
    }

    @Test
    @DisplayName("合法 EQ 条件发布成功")
    void validConditionPublished() {
        String json = policy("c-1.0",
                """
                [{"attribute":"department","operator":"EQ","value":"platform"}]
                """);
        assertEquals("c-1.0", governance.publishJson(json, "ok").getPolicy().getPolicyVersion());
    }

    @Test
    @DisplayName("缺少 attribute -> INVALID_CONDITION")
    void missingAttribute() {
        expectFailure(policy("c-1.1",
                "[{\"operator\":\"EQ\",\"value\":\"platform\"}]"),
                FailureReason.INVALID_CONDITION, "missing-attribute");
    }

    @Test
    @DisplayName("缺少 operator -> INVALID_CONDITION（与不支持的比较方式区分）")
    void missingOperator() {
        expectFailure(policy("c-1.2",
                "[{\"attribute\":\"department\",\"value\":\"platform\"}]"),
                FailureReason.INVALID_CONDITION, "missing-operator");
    }

    @Test
    @DisplayName("不认识的比较方式 -> UNSUPPORTED_OPERATOR")
    void unsupportedOperator() {
        expectFailure(policy("c-1.3",
                "[{\"attribute\":\"department\",\"operator\":\"REGEX\",\"value\":\"p.*\"}]"),
                FailureReason.UNSUPPORTED_OPERATOR, "unsupported-operator");
    }

    @Test
    @DisplayName("EQ 的 value 为空 -> INVALID_CONDITION")
    void emptyScalarValue() {
        expectFailure(policy("c-1.4",
                "[{\"attribute\":\"department\",\"operator\":\"EQ\",\"value\":\"\"}]"),
                FailureReason.INVALID_CONDITION, "empty-value");
    }

    @Test
    @DisplayName("IN 的 values 缺失/为空 -> INVALID_CONDITION")
    void emptyInValues() {
        expectFailure(policy("c-1.5",
                "[{\"attribute\":\"department\",\"operator\":\"IN\",\"values\":[]}]"),
                FailureReason.INVALID_CONDITION, "empty-in-values");
    }

    @Test
    @DisplayName("IN 的 values 含空元素 -> INVALID_CONDITION")
    void blankElementInValues() {
        expectFailure(policy("c-1.6",
                "[{\"attribute\":\"department\",\"operator\":\"IN\",\"values\":[\"platform\",\"\"]}]"),
                FailureReason.INVALID_CONDITION, "blank-element");
    }

    @Test
    @DisplayName("数值比较 value 非数字 -> INVALID_CONDITION")
    void nonNumericThreshold() {
        expectFailure(policy("c-1.7",
                "[{\"attribute\":\"clearanceLevel\",\"operator\":\"GTE\",\"value\":\"high\"}]"),
                FailureReason.INVALID_CONDITION, "non-numeric-threshold");
    }

    @Test
    @DisplayName("条件里夹塞未知字段 -> UNKNOWN_FIELD")
    void unknownFieldInCondition() {
        expectFailure(policy("c-1.8",
                "[{\"attribute\":\"department\",\"operator\":\"EQ\",\"value\":\"platform\","
                        + "\"caseSensitive\":false}]"),
                FailureReason.UNKNOWN_FIELD, "unknown-condition-field");
    }

    @Test
    @DisplayName("条件完全相同但 effect 相反 -> CONFLICTING_RULES")
    void conflictingRulesWithSameConditions() {
        String json = """
                {
                  "policyVersion": "c-1.9",
                  "schemaVersion": "1.0",
                  "rules": [
                    {"id":"allow1","effect":"ALLOW","roles":["engineer"],
                     "resourceType":"document","maxSensitivity":3,"actions":["read"],
                     "requiredEnvironment":{},
                     "subjectConditions":[{"attribute":"department","operator":"EQ","value":"platform"}]},
                    {"id":"deny1","effect":"DENY","roles":["engineer"],
                     "resourceType":"document","maxSensitivity":3,"actions":["read"],
                     "requiredEnvironment":{},
                     "subjectConditions":[{"attribute":"department","operator":"EQ","value":"platform"}]}
                  ]
                }
                """;
        expectFailure(json, FailureReason.CONFLICTING_RULES, "conflict-same-conditions");
    }

    @Test
    @DisplayName("条件取值不同不构成冲突，可发布")
    void differentConditionsNoConflict() {
        String json = """
                {
                  "policyVersion": "c-2.0",
                  "schemaVersion": "1.0",
                  "rules": [
                    {"id":"allow1","effect":"ALLOW","roles":["engineer"],
                     "resourceType":"document","maxSensitivity":3,"actions":["read"],
                     "requiredEnvironment":{},
                     "subjectConditions":[{"attribute":"department","operator":"EQ","value":"platform"}]},
                    {"id":"deny1","effect":"DENY","roles":["engineer"],
                     "resourceType":"document","maxSensitivity":3,"actions":["read"],
                     "requiredEnvironment":{},
                     "subjectConditions":[{"attribute":"department","operator":"EQ","value":"security"}]}
                  ]
                }
                """;
        assertEquals("c-2.0", governance.publishJson(json, "no-conflict").getPolicy().getPolicyVersion());
        log.info("条件不同的 ALLOW/DENY 规则不构成冲突，发布成功");
    }

    @Test
    @DisplayName("老格式策略（无 subjectConditions 字段）照常发布（向后兼容）")
    void legacyPolicyStillValid() {
        String legacy = """
                {
                  "policyVersion": "c-legacy",
                  "schemaVersion": "1.0",
                  "rules": [
                    {"id":"old1","effect":"ALLOW","roles":["engineer"],
                     "resourceType":"document","maxSensitivity":3,"actions":["read"],
                     "requiredEnvironment":{}}
                  ]
                }
                """;
        assertEquals("c-legacy", governance.publishJson(legacy, "legacy").getPolicy().getPolicyVersion());
    }
}
