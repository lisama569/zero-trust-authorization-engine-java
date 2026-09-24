package com.github.lisama569.zerotrustauthorizationenginejava.model;

import java.util.Map;

/** 环境上下文：设备可信度、网络位置、时间段等属性键值 */
public final class EnvironmentContext {
    private final Map<String, String> attributes;

    public EnvironmentContext(Map<String, String> attributes) {
        this.attributes = attributes;
    }

    public Map<String, String> getAttributes() { return attributes; }
}
