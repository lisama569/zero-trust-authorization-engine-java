package com.github.lisama569.zerotrustauthorizationenginejava.validation;

/** 策略加载/校验/发布/回滚失败时抛出，携带可区分的失败码与细节。 */
public class PolicyValidationException extends RuntimeException {

    private final PolicyFailureCode failureCode;

    public PolicyValidationException(PolicyFailureCode failureCode, String message) {
        super(message);
        this.failureCode = failureCode;
    }

    public PolicyFailureCode getFailureCode() {
        return failureCode;
    }
}
