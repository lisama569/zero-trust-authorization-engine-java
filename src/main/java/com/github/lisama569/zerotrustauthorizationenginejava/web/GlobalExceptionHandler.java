package com.github.lisama569.zerotrustauthorizationenginejava.web;

import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.github.lisama569.zerotrustauthorizationenginejava.validation.PolicyValidationException;
import com.github.lisama569.zerotrustauthorizationenginejava.web.dto.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 统一异常处理：所有对外失败都以 {@link ErrorResponse} 表达，
 * 内部异常不直接穿透，细节只进服务日志。
 *
 * <p>状态码约定：
 * <ul>
 *   <li>422：策略语义/版本问题（携带精确 failureCode）；</li>
 *   <li>400：请求体不可读、未知字段、结构错误；</li>
 *   <li>500：未预期内部错误（对外只返回固定文案）。</li>
 * </ul>
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(PolicyValidationException.class)
    public ResponseEntity<ErrorResponse> handlePolicy(PolicyValidationException e) {
        log.warn("策略处理被拒绝: code={}, message={}", e.getFailureCode(), e.getMessage());
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
                .body(new ErrorResponse(e.getFailureCode().name(), e.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleNotReadable(HttpMessageNotReadableException e) {
        Throwable cause = e.getCause();
        if (cause instanceof UnrecognizedPropertyException upe) {
            String msg = "请求包含未知字段: " + upe.getPropertyName()
                    + "（位置: " + upe.getLocation() + "）";
            log.warn("请求反序列化失败（未知字段）: {}", msg);
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse("UNKNOWN_FIELD", msg));
        }
        log.warn("请求体不可读: {}", cause == null ? e.getMessage() : cause.getMessage());
        return ResponseEntity.badRequest()
                .body(new ErrorResponse("MALFORMED_JSON",
                        "请求体不是合法 JSON 或字段类型错误"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(Exception e) {
        log.error("未预期的内部异常", e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorResponse("INTERNAL_ERROR", "服务内部错误，请联系管理员并核对日志"));
    }
}
