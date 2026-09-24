package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Policy;
import com.github.lisama569.zerotrustauthorizationenginejava.validation.PolicyFailureCode;
import com.github.lisama569.zerotrustauthorizationenginejava.validation.PolicyParser;
import com.github.lisama569.zerotrustauthorizationenginejava.validation.PolicyValidationException;
import com.github.lisama569.zerotrustauthorizationenginejava.validation.PolicyValidator;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 策略严格解析与语义校验测试：每类失败原因必须可区分。 */
class PolicyParserValidatorTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyParserValidatorTest.class);

    private final ObjectMapper mapper = new ObjectMapper();
    private final PolicyParser parser = new PolicyParser();
    private final PolicyValidator validator = new PolicyValidator();

    private JsonNode json(String s) {
        try {
            return mapper.readTree(s);
        } catch (Exception e) {
            throw new IllegalArgumentException("测试 JSON 不合法: " + s, e);
        }
    }

    private void assertFailure(String json, PolicyFailureCode expected, String caseName) {
        PolicyValidationException ex = assertThrows(PolicyValidationException.class,
                () -> parser.parse(json(json)));
        log.info("[用例 {}] 期望失败码={}, 实际={}, 细节={}",
                caseName, expected, ex.getFailureCode(), ex.getMessage());
        assertEquals(expected, ex.getFailureCode());
    }

    private static final String VALID_RULE = """
            {
              "id": "r1",
              "effect": "ALLOW",
              "conditions": [
                {"source": "SUBJECT", "attribute": "role", "op": "eq", "expected": "admin"}
              ]
            }
            """;

    @Test
    void validPolicyParses() {
        Policy p = parser.parse(json("""
                {
                  "schemaVersion": 1,
                  "policyId": "root",
                  "version": "v1",
                  "rules": [%s]
                }
                """.formatted(VALID_RULE)));
        validator.validate(p);
        log.info("[用例 valid] 解析成功: version={}, rules={}", p.version(), p.rules().size());
        assertEquals("v1", p.version());
        assertEquals(1, p.rules().size());
    }

    @Test
    void unknownTopLevelFieldRejected() {
        assertFailure("""
                {"schemaVersion": 1, "policyId": "root", "version": "v1",
                 "rules": [], "priority": 99}
                """, PolicyFailureCode.UNKNOWN_FIELD, "顶层未知字段");
    }

    @Test
    void unknownNestedFieldRejected() {
        assertFailure("""
                {"schemaVersion": 1, "policyId": "root", "version": "v1",
                 "rules": [{"id": "r1", "effect": "ALLOW",
                            "conditions": [], "breakGlass": true}]}
                """, PolicyFailureCode.UNKNOWN_FIELD, "规则未知字段");
    }

    @Test
    void invalidEffectRejected() {
        assertFailure("""
                {"schemaVersion": 1, "policyId": "root", "version": "v1",
                 "rules": [{"id": "r1", "effect": "MAYBE", "conditions": []}]}
                """, PolicyFailureCode.INVALID_ENUM_VALUE, "非法 effect");
    }

    @Test
    void invalidSourceRejected() {
        assertFailure("""
                {"schemaVersion": 1, "policyId": "root", "version": "v1",
                 "rules": [{"id": "r1", "effect": "ALLOW",
                   "conditions": [{"source": "REQUESTER", "attribute": "r",
                                   "op": "eq", "expected": "x"}]}]}
                """, PolicyFailureCode.INVALID_ENUM_VALUE, "非法 source");
    }

    @Test
    void invalidOperatorRejected() {
        assertFailure("""
                {"schemaVersion": 1, "policyId": "root", "version": "v1",
                 "rules": [{"id": "r1", "effect": "ALLOW",
                   "conditions": [{"source": "SUBJECT", "attribute": "r",
                                   "op": "matches", "expected": "x"}]}]}
                """, PolicyFailureCode.INVALID_ENUM_VALUE, "非法 op");
    }

    @Test
    void unsupportedSchemaVersionRejected() {
        assertFailure("""
                {"schemaVersion": 99, "policyId": "root", "version": "v1", "rules": []}
                """, PolicyFailureCode.SCHEMA_VERSION_INCOMPATIBLE, "schema 版本不兼容");
    }

    @Test
    void missingRequiredFieldRejected() {
        assertFailure("""
                {"schemaVersion": 1, "policyId": "root", "rules": []}
                """, PolicyFailureCode.MISSING_REQUIRED_FIELD, "缺少 version");
    }

    @Test
    void malformedStructureRejected() {
        assertFailure("""
                {"schemaVersion": 1, "policyId": "root", "version": "v1",
                 "rules": {"not": "array"}}
                """, PolicyFailureCode.MALFORMED_JSON, "rules 非数组");
    }

    @Test
    void duplicateRuleIdsRejectedByValidator() {
        Policy p = parser.parse(json("""
                {"schemaVersion": 1, "policyId": "root", "version": "v1",
                 "rules": [
                   {"id": "dup", "effect": "ALLOW", "conditions": []},
                   {"id": "dup", "effect": "DENY", "conditions": []}
                 ]}
                """));
        PolicyValidationException ex = assertThrows(PolicyValidationException.class,
                () -> validator.validate(p));
        log.info("[用例 重复id] failureCode={}, 细节={}",
                ex.getFailureCode(), ex.getMessage());
        assertEquals(PolicyFailureCode.DUPLICATE_RULE_ID, ex.getFailureCode());
    }

    @Test
    void conflictingRulesRejectedByValidator() {
        Policy p = parser.parse(json("""
                {"schemaVersion": 1, "policyId": "root", "version": "v1",
                 "rules": [
                   {"id": "a", "effect": "ALLOW",
                    "conditions": [
                      {"source": "SUBJECT", "attribute": "role", "op": "eq",
                       "expected": "admin"}]},
                   {"id": "b", "effect": "DENY",
                    "conditions": [
                      {"source": "SUBJECT", "attribute": "role", "op": "eq",
                       "expected": "admin"}]}
                 ]}
                """));
        PolicyValidationException ex = assertThrows(PolicyValidationException.class,
                () -> validator.validate(p));
        log.info("[用例 冲突规则] failureCode={}, 细节={}",
                ex.getFailureCode(), ex.getMessage());
        assertEquals(PolicyFailureCode.CONFLICTING_RULES, ex.getFailureCode());
        assertTrue(ex.getMessage().contains("a"));
        assertTrue(ex.getMessage().contains("b"));
    }

    @Test
    void sameConditionsDifferentOrderIsConflict() {
        // 条件声明顺序不同但集合相同，依然是冲突
        Policy p = parser.parse(json("""
                {"schemaVersion": 1, "policyId": "root", "version": "v1",
                 "rules": [
                   {"id": "a", "effect": "ALLOW", "conditions": [
                      {"source": "RESOURCE", "attribute": "s", "op": "eq", "expected": "1"},
                      {"source": "SUBJECT", "attribute": "r", "op": "eq", "expected": "admin"}]},
                   {"id": "b", "effect": "DENY", "conditions": [
                      {"source": "SUBJECT", "attribute": "r", "op": "eq", "expected": "admin"},
                      {"source": "RESOURCE", "attribute": "s", "op": "eq", "expected": "1"}]}
                 ]}
                """));
        PolicyValidationException ex = assertThrows(PolicyValidationException.class,
                () -> validator.validate(p));
        log.info("[用例 顺序无关冲突] failureCode={}", ex.getFailureCode());
        assertEquals(PolicyFailureCode.CONFLICTING_RULES, ex.getFailureCode());
    }
}
