package com.github.lisama569.zerotrustauthorizationenginejava.web.dto;

/** 统一错误响应：可区分失败码 + 细节。 */
public record ErrorResponse(String code, String message) {
}
