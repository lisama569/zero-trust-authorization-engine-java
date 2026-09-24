package com.github.lisama569.zerotrustauthorizationenginejava.model;

/**
 * 对外评估结论。outcome 可区分五种结果；
 * version 为实际生效的策略版本；matchedRuleId 为命中规则；
 * reason 为判定依据摘要。
 */
public record DecisionResult(
        DecisionOutcome outcome,
        String version,
        String matchedRuleId,
        String reason
) {
}
