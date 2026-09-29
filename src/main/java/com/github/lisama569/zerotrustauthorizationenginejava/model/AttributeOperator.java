package com.github.lisama569.zerotrustauthorizationenginejava.model;

/**
 * 主体属性条件支持的比较方式。
 * EQ/NE/IN/NOT_IN 按字符串比较；GT/GTE/LT/LTE 按数值比较。
 */
public enum AttributeOperator {
    EQ, NE, IN, NOT_IN, GT, GTE, LT, LTE;

    /** 是否为数值比较（要求条件值与主体属性值均可解析为数值） */
    public boolean isNumeric() {
        return this == GT || this == GTE || this == LT || this == LTE;
    }

    /** 是否为取值集合比较（条件值为非空数组） */
    public boolean isSetBased() {
        return this == IN || this == NOT_IN;
    }
}
