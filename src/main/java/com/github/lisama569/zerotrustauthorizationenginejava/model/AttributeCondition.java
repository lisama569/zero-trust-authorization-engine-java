package com.github.lisama569.zerotrustauthorizationenginejava.model;

import java.util.List;

/**
 * 针对主体单个属性的附加条件（不可变）。
 *
 * <p>语义：从主体属性表中取 {@code attribute} 对应的值，按 {@code operator} 与
 * {@code value} / {@code values} 比较。属性键在主体上完全缺失（未提供）与
 * 属性存在但比较不通过是两种不同结果，由评估器显式区分，绝不混淆。</p>
 */
public final class AttributeCondition {

    private final String attribute;
    private final ConditionOperator operator;
    private final String value;
    private final List<String> values;

    public AttributeCondition(String attribute, ConditionOperator operator,
                              String value, List<String> values) {
        this.attribute = attribute;
        this.operator = operator;
        this.value = value;
        this.values = values;
    }

    public String getAttribute() { return attribute; }
    public ConditionOperator getOperator() { return operator; }
    public String getValue() { return value; }
    public List<String> getValues() { return values; }
}
