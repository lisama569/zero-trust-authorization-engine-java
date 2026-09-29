package com.github.lisama569.zerotrustauthorizationenginejava.model;

import java.util.List;

/**
 * 主体属性条件（不可变）。
 *
 * attribute 为主体属性键；operator 为比较方式；
 * 标量比较（EQ/NE/GT/GTE/LT/LTE）取 values[0]，
 * 集合比较（IN/NOT_IN）取整个 values。
 */
public final class AttributeCondition {
    private final String attribute;
    private final AttributeOperator operator;
    private final List<String> values;

    public AttributeCondition(String attribute, AttributeOperator operator, List<String> values) {
        this.attribute = attribute;
        this.operator = operator;
        this.values = values;
    }

    public String getAttribute() { return attribute; }
    public AttributeOperator getOperator() { return operator; }
    public List<String> getValues() { return values; }
}
