package com.github.lisama569.zerotrustauthorizationenginejava.model;

/**
 * 单条匹配条件：从 source 指定的上下文中取 attribute，用 op 与 expected 比较。
 */
public record RuleCondition(
        AttributeSource source,
        String attribute,
        String op,
        String expected
) {
}
