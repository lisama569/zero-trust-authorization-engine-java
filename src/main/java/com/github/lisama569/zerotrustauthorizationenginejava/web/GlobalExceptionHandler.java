package com.github.lisama569.zerotrustauthorizationenginejava.web;

import com.github.lisama569.zerotrustauthorizationenginejava.exception.PolicyException;
import com.github.lisama569.zerotrustauthorizationenginejava.model.FailureReason;
import com.github.lisama569.zerotrustauthorizationenginejava.web.dto.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 全局异常处理：
 * - PolicyException 按可区分的 FailureReason 返回 422；
 * - 请求体无法读取 -> MALFORMED_POLICY / INVALID_POLICY；
 * - 其余未预期异常 -> INTERNAL_ERROR，不回传堆栈。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(PolicyException.class)
    public org.springframework.http.ResponseEntity<ErrorResponse> handlePolicy(PolicyException e) {
        log.warn("策略治理失败 reason={} message={}", e.getReason(), e.getMessage());
        return org.springframework.http.ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
                .body(new ErrorResponse(e.getReason().name(), e.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public org.springframework.http.ResponseEntity<ErrorResponse> handleUnreadable(
            HttpMessageNotReadableException e) {
        return org.springframework.http.ResponseEntity.badRequest()
                .body(new ErrorResponse(FailureReason.INVALID_POLICY.name(),
                        "请求体无法解析: " + rootMessage(e)));
    }

    @ExceptionHandler(Exception.class)
    public org.springframework.http.ResponseEntity<ErrorResponse> handleOther(Exception e) {
        log.error("未预期的服务异常", e);
        return org.springframework.http.ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorResponse(FailureReason.INTERNAL_ERROR.name(), "服务内部错误"));
    }

    private String rootMessage(Throwable t) {
        Throwable cur = t;
        while (cur.getCause() != null && cur.getCause() != cur) {
            cur = cur.getCause();
        }
        return cur.getMessage() == null ? "格式错误" : cur.getMessage();
    }
}
