package com.github.lisama569.zerotrustauthorizationenginejava.engine;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AttributeCondition;
import com.github.lisama569.zerotrustauthorizationenginejava.model.ConditionOperator;

import java.math.BigDecimal;
import java.util.Map;

/**
 * 主体属性条件匹配器。
 *
 * <p>三种结果严格区分：</p>
 * <ul>
 *   <li>{@link Result#MATCHED}：属性存在且条件成立；</li>
 *   <li>{@link Result#NOT_MATCHED}：属性存在（有值）但比较不通过，
 *       或数值比较时任一侧无法解析为数字（绝不把它误判成缺失）；</li>
 *   <li>{@link Result#MISSING}：主体根本未提供该属性或值为空白
 *       —— 信息缺失不得当作满足，也不得当作普通不满足。</li>
 * </ul>
 */
public final class AttributeConditionMatcher {

    public enum Result { MATCHED, NOT_MATCHED, MISSING }

    private AttributeConditionMatcher() {
    }

    public static Result matches(AttributeCondition condition, Map<String, String> subjectAttributes) {
        Map<String, String> attrs = subjectAttributes == null ? Map.of() : subjectAttributes;
        String actual = attrs.get(condition.getAttribute());
        if (actual == null || actual.isBlank()) {
            return Result.MISSING;
        }

        ConditionOperator op = condition.getOperator();
        return switch (op) {
            case EQ -> actual.equals(condition.getValue()) ? Result.MATCHED : Result.NOT_MATCHED;
            case NE -> !actual.equals(condition.getValue()) ? Result.MATCHED : Result.NOT_MATCHED;
            case IN -> condition.getValues().contains(actual) ? Result.MATCHED : Result.NOT_MATCHED;
            case NOT_IN -> !condition.getValues().contains(actual)
                    ? Result.MATCHED : Result.NOT_MATCHED;
            case GT, GTE, LT, LTE -> compareNumeric(op, condition.getValue(), actual);
        };
    }

    private static Result compareNumeric(ConditionOperator op, String expected, String actual) {
        BigDecimal expectedNumber;
        BigDecimal actualNumber;
        try {
            expectedNumber = new BigDecimal(expected.trim());
            actualNumber = new BigDecimal(actual.trim());
        } catch (NumberFormatException e) {
            // 属性在、但不是可比较的数值：属于“有值但不满足”，不是缺失
            return Result.NOT_MATCHED;
        }
        int cmp = actualNumber.compareTo(expectedNumber);
        boolean ok = switch (op) {
            case GT -> cmp > 0;
            case GTE -> cmp >= 0;
            case LT -> cmp < 0;
            case LTE -> cmp <= 0;
            default -> false;
        };
        return ok ? Result.MATCHED : Result.NOT_MATCHED;
    }
}
