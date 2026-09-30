package com.github.lisama569.zerotrustauthorizationenginejava.audit;

/**
 * 审计历史不可复核异常：启动重放判定“历史整体丢失”后，
 * 在显式恢复之前任何追加都会被拒绝并抛出本异常，
 * 防止系统默默从零续写、覆盖不可复核的事实。
 */
public class AuditHistoryUnavailableException extends RuntimeException {

    public AuditHistoryUnavailableException(String message) {
        super(message);
    }
}
