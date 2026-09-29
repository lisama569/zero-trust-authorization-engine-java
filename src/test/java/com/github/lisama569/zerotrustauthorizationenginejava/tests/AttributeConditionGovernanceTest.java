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
 * 属性条件在发布阶段的校验测试：
 * 合法条件可发布、不认识的比较方式/空取值/非数值/未知字段被可区分地拒绝；
 * 属性条件参与冲突判定；老的 1.0 策略（无属性条件）照常发布。
 */
class AttributeConditionGovernanceTest {

    private static final Logger log = LoggerFactory.getLogger(AttributeConditionGovernanceTest.class);

    private PolicyGovernanceService governance;

    private static String policy(String version, String conditionClause) {
        return """
                {
                  "policyVersion": "%s",
                  "schemaVersion": "1.1",
                  "rules": [
                    {"id":"ac1","name":"attr-rule","effect":"ALLOW","roles":["engineer"],
                     "resourceType":"document","maxSensitivity":5,"actions":["read"],
                     "requiredEnvironment":{}
                     %s
                    }
                  ]
                }
                """.formatted(version, conditionClause);
    }

    @BeforeEach
    void setUp() {
        PolicyVersionManager vm = new PolicyVersionManager(new PolicyValidator());
        governance = new PolicyGovernanceService(new PolicyParser(), vm);
    }

    private void expectReject(String json, FailureReason reason, String tag) {
        PolicyException ex = assertThrows(PolicyException.class,
                () -> governance.publishJson(json, tag), tag);
        assertEquals(reason, ex.getReason(), tag + " 实际原因=" + ex.getReason());
        log.info("[{}] 如预期被拒 reason={} message={}", tag, ex.getReason(), ex.getMessage());
    }

    @Test
    @DisplayName("八种比较方式的合法属性条件均可发布")
    void allOperatorsAccepted() {
        String[][] cases = {
                {"EQ", "\"value\":\"full-time\""},
                {"NE", "\"value\":\"contract\""},
                {"IN", "\"values\":[\"security\",\"compliance\"]"},
                {"NOT_IN", "\"values\":[\"contract\"]"},
                {"GT", "\"value\":3"},
                {"GTE", "\"value\":3"},
                {"LT", "\"value\":5"},
                {"LTE", "\"value\":5"}
        };
        int i = 0;
        for (String[] c : cases) {
            String clause = ",\"attributeConditions\":[{\"attribute\":\"employment\","
                    + "\"operator\":\"" + c[0] + "\"," + c[1] + "}]";
            String v = "8.1." + (i++);
            assertDoesNotThrow(() -> governance.publishJson(policy(v, clause), c[0]),
                    c[0] + " 应可发布");
        }
        log.info("八种比较方式全部发布成功");
    }

    @Test
    @DisplayName("不认识的比较方式 -> UNSUPPORTED_OPERATOR")
    void unknownOperatorRejected() {
        String clause = ",\"attributeConditions\":[{\"attribute\":\"employment\","
                + "\"operator\":\"REGEX_MATCH\",\"value\":\"x\"}]";
        expectReject(policy("8.2.1", clause), FailureReason.UNSUPPORTED_OPERATOR, "unknown-op");
    }

    @Test
    @DisplayName("条件缺少 operator -> UNSUPPORTED_OPERATOR")
    void missingOperatorRejected() {
        String clause = ",\"attributeConditions\":[{\"attribute\":\"employment\","
                + "\"value\":\"x\"}]";
        expectReject(policy("8.2.2", clause), FailureReason.UNSUPPORTED_OPERATOR, "missing-op");
    }

    @Test
    @DisplayName("标量条件缺少 value / 空白 value -> INVALID_POLICY")
    void missingValueRejected() {
        String noValue = ",\"attributeConditions\":[{\"attribute\":\"employment\","
                + "\"operator\":\"EQ\"}]";
        expectReject(policy("8.2.3", noValue), FailureReason.INVALID_POLICY, "no-value");

        String blankValue = ",\"attributeConditions\":[{\"attribute\":\"employment\","
                + "\"operator\":\"EQ\",\"value\":\"  \"}]";
        expectReject(policy("8.2.4", blankValue), FailureReason.INVALID_POLICY, "blank-value");
    }

    @Test
    @DisplayName("集合条件 values 为空或含空项 -> INVALID_POLICY")
    void emptySetRejected() {
        String empty = ",\"attributeConditions\":[{\"attribute\":\"department\","
                + "\"operator\":\"IN\",\"values\":[]}]";
        expectReject(policy("8.2.5", empty), FailureReason.INVALID_POLICY, "empty-set");

        String blankItem = ",\"attributeConditions\":[{\"attribute\":\"department\","
                + "\"operator\":\"NOT_IN\",\"values\":[\"security\",\" \"]}]";
        expectReject(policy("8.2.6", blankItem), FailureReason.INVALID_POLICY, "blank-item");
    }

    @Test
    @DisplayName("数值比较的 value 不是数值 -> INVALID_POLICY")
    void nonNumericRejected() {
        String clause = ",\"attributeConditions\":[{\"attribute\":\"clearanceLevel\","
                + "\"operator\":\"GTE\",\"value\":\"high\"}]";
        expectReject(policy("8.2.7", clause), FailureReason.INVALID_POLICY, "non-numeric");
    }

    @Test
    @DisplayName("缺少 attribute 键名 -> INVALID_POLICY")
    void missingAttributeNameRejected() {
        String clause = ",\"attributeConditions\":[{\"operator\":\"EQ\",\"value\":\"x\"}]";
        expectReject(policy("8.2.8", clause), FailureReason.INVALID_POLICY, "no-attr-name");
    }

    @Test
    @DisplayName("条件取值写成对象/数组 -> MALFORMED_POLICY")
    void nonScalarValueRejected() {
        String clause = ",\"attributeConditions\":[{\"attribute\":\"employment\","
                + "\"operator\":\"EQ\",\"value\":{\"nested\":1}}]";
        expectReject(policy("8.2.9", clause), FailureReason.MALFORMED_POLICY, "object-value");
    }

    @Test
    @DisplayName("条件里夹带未知字段 -> UNKNOWN_FIELD")
    void unknownFieldInConditionRejected() {
        String clause = ",\"attributeConditions\":[{\"attribute\":\"employment\","
                + "\"operator\":\"EQ\",\"value\":\"x\",\"caseSensitive\":false}]";
        expectReject(policy("8.2.10", clause), FailureReason.UNKNOWN_FIELD, "unknown-cond-field");
    }

    @Test
    @DisplayName("属性条件完全相同但 effect 相反 -> CONFLICTING_RULES；条件不同则不冲突")
    void attributeConditionsParticipateInConflict() {
        String body = """
                {
                  "policyVersion": "8.3.1",
                  "schemaVersion": "1.1",
                  "rules": [
                    {"id":"allow1","effect":"ALLOW","roles":["engineer"],
                     "resourceType":"document","maxSensitivity":5,"actions":["read"],
                     "requiredEnvironment":{},
                     "attributeConditions":[{"attribute":"employment","operator":"EQ",
                     "value":"full-time"}]},
                    {"id":"deny1","effect":"DENY","roles":["engineer"],
                     "resourceType":"document","maxSensitivity":5,"actions":["read"],
                     "requiredEnvironment":{},
                     "attributeConditions":[{"attribute":"employment","operator":"EQ",
                     "value":"full-time"}]}
                  ]
                }
                """;
        expectReject(body, FailureReason.CONFLICTING_RULES, "same-conditions-conflict");

        // 属性条件不同（一个 EQ full-time，一个 EQ contract）不算同一匹配维度，不冲突
        String fine = body.replace("8.3.1", "8.3.2")
                .replace("\"id\":\"deny1\"", "\"id\":\"deny2\"")
                .replaceFirst("\"value\":\"full-time\"(?!.*full-time)", "\"value\":\"contract\"");
        // 上面 replaceFirst 只替换第一次出现；为稳妥直接手工构造
        String finePolicy = """
                {
                  "policyVersion": "8.3.3",
                  "schemaVersion": "1.1",
                  "rules": [
                    {"id":"allow1","effect":"ALLOW","roles":["engineer"],
                     "resourceType":"document","maxSensitivity":5,"actions":["read"],
                     "requiredEnvironment":{},
                     "attributeConditions":[{"attribute":"employment","operator":"EQ",
                     "value":"full-time"}]},
                    {"id":"deny2","effect":"DENY","roles":["engineer"],
                     "resourceType":"document","maxSensitivity":5,"actions":["read"],
                     "requiredEnvironment":{},
                     "attributeConditions":[{"attribute":"employment","operator":"EQ",
                     "value":"contract"}]}
                  ]
                }
                """;
        assertDoesNotThrow(() -> governance.publishJson(finePolicy, "different-conditions"));
        log.info("属性条件不同的 ALLOW/DENY 规则不构成冲突，发布成功");
    }

    @Test
    @DisplayName("老 1.0 策略（无 attributeConditions、schemaVersion=1.0）照常发布")
    void legacyPolicyStillPublishes() {
        String legacy = """
                {
                  "policyVersion": "8.4.1",
                  "schemaVersion": "1.0",
                  "rules": [
                    {"id":"legacy1","effect":"ALLOW","roles":["engineer"],
                     "resourceType":"document","maxSensitivity":3,"actions":["read"],
                     "requiredEnvironment":{}}
                  ]
                }
                """;
        assertDoesNotThrow(() -> governance.publishJson(legacy, "legacy"));
        log.info("老版本 1.0 策略无属性条件，照常发布成功");
    }
}
