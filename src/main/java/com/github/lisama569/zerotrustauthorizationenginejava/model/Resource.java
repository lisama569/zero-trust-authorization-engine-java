package com.github.lisama569.zerotrustauthorizationenginejava.model;

import java.util.Map;

/** 资源：标识 + 属性表（如 sensitivityLevel）。 */
public record Resource(String id, Map<String, String> attributes) {
}
