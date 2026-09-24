package com.github.lisama569.zerotrustauthorizationenginejava.model;

/**
 * 对外可区分的授权结论：
 * PERMIT 允许 / DENY 显式拒绝 / CONTEXT_MISSING 上下文缺失 /
 * POLICY_NOT_MATCHED 无规则匹配（默认拒绝）/ EVALUATION_FAILED 评估失败。
 */
public enum DecisionOutcome {
    PERMIT,
    DENY,
    CONTEXT_MISSING,
    POLICY_NOT_MATCHED,
    EVALUATION_FAILED
}
