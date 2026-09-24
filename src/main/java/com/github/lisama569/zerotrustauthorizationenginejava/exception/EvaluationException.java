package com.github.lisama569.zerotrustauthorizationenginejava.exception;

/** 评估内部异常：不直接穿透到对外结果，由服务层转换为 EVALUATION_FAILED */
public class EvaluationException extends RuntimeException {
    public EvaluationException(String message) {
        super(message);
    }

    public EvaluationException(String message, Throwable cause) {
        super(message, cause);
    }
}
