package com.github.lisama569.zerotrustauthorizationenginejava.model;

import java.util.List;

/**
 * 策略：不可变值对象。schemaVersion 用于版本兼容校验，
 * version 是发布时的策略版本标识，rules 按声明顺序求值。
 */
public record Policy(
        int schemaVersion,
        String policyId,
        String version,
        List<Rule> rules
) {
}
