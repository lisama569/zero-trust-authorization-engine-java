package com.github.lisama569.zerotrustauthorizationenginejava.model;

import java.util.Map;

/** 环境上下文：网络位置、时间窗等属性。 */
public record EnvironmentContext(Map<String, String> attributes) {
}
