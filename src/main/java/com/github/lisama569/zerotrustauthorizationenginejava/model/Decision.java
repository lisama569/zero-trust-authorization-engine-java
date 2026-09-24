package com.github.lisama569.zerotrustauthorizationenginejava.model;

/**
 * 授权评估的最终判定。
 * 每种结果都必须可被调用方区分。
 */
public enum Decision {
    /** 至少一条 ALLOW 规则匹配且无冲突拒绝 */
    ALLOW,
    /** 显式拒绝：命中 DENY 规则 */
    DENY,
    /** 上下文缺失：评估所需的主体/资源/环境属性未提供 */
    CONTEXT_MISSING,
    /** 策略不匹配：无规则命中，默认拒绝 */
    POLICY_NOT_MATCHED,
    /** 评估失败：内部异常，细节不穿透到对外结果 */
    EVALUATION_FAILED
}
