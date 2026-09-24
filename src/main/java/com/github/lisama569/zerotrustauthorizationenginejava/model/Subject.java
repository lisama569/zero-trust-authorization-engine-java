package com.github.lisama569.zerotrustauthorizationenginejava.model;

import java.util.Map;

/** 主体：身份标识 + 属性表。 */
public record Subject(String id, Map<String, String> attributes) {
}
