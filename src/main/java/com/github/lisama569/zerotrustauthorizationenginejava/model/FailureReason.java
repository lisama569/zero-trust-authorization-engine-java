package com.github.lisama569.zerotrustauthorizationenginejava.model;

/**
 * 可区分的失败原因，用于策略治理与评估的对外错误反馈。
 */
public enum FailureReason {
    /** 策略 JSON 无法解析 */
    MALFORMED_POLICY,
    /** 策略包含未知字段 */
    UNKNOWN_FIELD,
    /** 策略结构/取值非法（缺必填字段、非法枚举等） */
    INVALID_POLICY,
    /** 属性条件使用了引擎不认识的比较方式 */
    UNSUPPORTED_OPERATOR,
    /** 同一规则同时声明 ALLOW 与 DENY 等冲突 */
    CONFLICTING_RULES,
    /** 回滚目标版本不存在 */
    VERSION_NOT_FOUND,
    /** 评估上下文缺少必需属性 */
    MISSING_CONTEXT,
    /** 审计历史整体丢失、无法复核（需显式恢复后才能继续写入） */
    AUDIT_HISTORY_UNVERIFIABLE,
    /** 内部错误，细节不外泄 */
    INTERNAL_ERROR
}
