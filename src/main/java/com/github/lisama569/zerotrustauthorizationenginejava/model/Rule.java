package com.github.lisama569.zerotrustauthorizationenginejava.model;

import java.util.List;

/**
 * 授权规则：条件全部满足时命中，命中后产生 effect。
 */
public record Rule(
        String id,
        Effect effect,
        List<RuleCondition> conditions
) {
}
