package com.github.lisama569.zerotrustauthorizationenginejava.web.dto;

/** 对外错误响应：携带可区分的失败原因，不含内部堆栈 */
public class ErrorResponse {
    private final String failureReason;
    private final String message;

    public ErrorResponse(String failureReason, String message) {
        this.failureReason = failureReason;
        this.message = message;
    }

    public String getFailureReason() { return failureReason; }
    public String getMessage() { return message; }
}
