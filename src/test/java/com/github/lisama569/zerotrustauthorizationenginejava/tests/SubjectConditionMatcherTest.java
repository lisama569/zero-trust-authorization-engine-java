package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.github.lisama569.zerotrustauthorizationenginejava.engine.AttributeConditionMatcher;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AttributeCondition;
import com.github.lisama569.zerotrustauthorizationenginejava.model.ConditionOperator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 主体属性条件匹配器测试：命中 / 属性在但不满足 / 属性缺失三态严格区分。
 */
class SubjectConditionMatcherTest {

    private static final Logger log = LoggerFactory.getLogger(SubjectConditionMatcherTest.class);

    private AttributeCondition c(String attr, ConditionOperator op, String value, List<String> values) {
        return new AttributeCondition(attr, op, value, values);
    }

    @Test
    @DisplayName("EQ：相等命中，不等不满足")
    void eqMatchAndMismatch() {
        AttributeCondition c = c("department", ConditionOperator.EQ, "platform", null);
        assertEquals(AttributeConditionMatcher.Result.MATCHED,
                AttributeConditionMatcher.matches(c, Map.of("department", "platform")));
        assertEquals(AttributeConditionMatcher.Result.NOT_MATCHED,
                AttributeConditionMatcher.matches(c, Map.of("department", "security")));
        log.info("EQ 命中/不满足区分正常");
    }

    @Test
    @DisplayName("NE：不等命中，相等不满足")
    void neMatch() {
        AttributeCondition c = c("employment", ConditionOperator.NE, "contract", null);
        assertEquals(AttributeConditionMatcher.Result.MATCHED,
                AttributeConditionMatcher.matches(c, Map.of("employment", "full-time")));
        assertEquals(AttributeConditionMatcher.Result.NOT_MATCHED,
                AttributeConditionMatcher.matches(c, Map.of("employment", "contract")));
    }

    @Test
    @DisplayName("IN / NOT_IN：集合归属判定")
    void collectionOps() {
        AttributeCondition in = c("department", ConditionOperator.IN, null,
                List.of("platform", "security"));
        assertEquals(AttributeConditionMatcher.Result.MATCHED,
                AttributeConditionMatcher.matches(in, Map.of("department", "security")));
        assertEquals(AttributeConditionMatcher.Result.NOT_MATCHED,
                AttributeConditionMatcher.matches(in, Map.of("department", "external")));

        AttributeCondition notIn = c("department", ConditionOperator.NOT_IN, null,
                List.of("external"));
        assertEquals(AttributeConditionMatcher.Result.MATCHED,
                AttributeConditionMatcher.matches(notIn, Map.of("department", "platform")));
        assertEquals(AttributeConditionMatcher.Result.NOT_MATCHED,
                AttributeConditionMatcher.matches(notIn, Map.of("department", "external")));
    }

    @Test
    @DisplayName("GT/GTE/LT/LTE：数值比较，含边界")
    void numericOps() {
        Map<String, String> level4 = Map.of("clearanceLevel", "4");
        assertEquals(AttributeConditionMatcher.Result.MATCHED,
                AttributeConditionMatcher.matches(c("clearanceLevel", ConditionOperator.GTE, "4", null), level4));
        assertEquals(AttributeConditionMatcher.Result.NOT_MATCHED,
                AttributeConditionMatcher.matches(c("clearanceLevel", ConditionOperator.GT, "4", null), level4));
        assertEquals(AttributeConditionMatcher.Result.MATCHED,
                AttributeConditionMatcher.matches(c("clearanceLevel", ConditionOperator.LTE, "4", null), level4));
        assertEquals(AttributeConditionMatcher.Result.NOT_MATCHED,
                AttributeConditionMatcher.matches(c("clearanceLevel", ConditionOperator.LT, "4", null), level4));
    }

    @Test
    @DisplayName("属性未提供或为空白 => MISSING，与不满足严格区分")
    void missingAttributeIsDistinct() {
        AttributeCondition c = c("clearanceLevel", ConditionOperator.GTE, "3", null);
        assertEquals(AttributeConditionMatcher.Result.MISSING,
                AttributeConditionMatcher.matches(c, Map.of()));
        assertEquals(AttributeConditionMatcher.Result.MISSING,
                AttributeConditionMatcher.matches(c, Map.of("clearanceLevel", "  ")));
        assertEquals(AttributeConditionMatcher.Result.MISSING,
                AttributeConditionMatcher.matches(c, null));
        log.info("属性缺失三态判定正常");
    }

    @Test
    @DisplayName("数值比较时实际值非数字 => NOT_MATCHED（不是 MISSING，更不是命中）")
    void nonNumericActualIsNotMatched() {
        AttributeCondition c = c("clearanceLevel", ConditionOperator.GTE, "3", null);
        assertEquals(AttributeConditionMatcher.Result.NOT_MATCHED,
                AttributeConditionMatcher.matches(c, Map.of("clearanceLevel", "high")));
    }
}
