package com.github.lisama569.zerotrustauthorizationenginejava.exception;

import com.github.lisama569.zerotrustauthorizationenginejava.model.FailureReason;

/** 策略治理（加载/校验/发布/回滚）失败，携带可区分原因 */
public class PolicyException extends RuntimeException {
    private final FailureReason reason;

    public PolicyException(FailureReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public FailureReason getReason() {
        return reason;
    }
}
