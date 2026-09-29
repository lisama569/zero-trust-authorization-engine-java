package com.github.lisama569.zerotrustauthorizationenginejava.model;

/**
 * 主体属性条件支持的比较方式。
 *
 * <ul>
 *   <li>{@link #EQ} / {@link #NE}：属性值等于 / 不等于单个期望值；</li>
 *   <li>{@link #IN} / {@link #NOT_IN}：属性值落在 / 不落在取值集合内；</li>
 *   <li>{@link #GT} / {@link #GTE} / {@link #LT} / {@link #LTE}：
 *       属性值与期望值按数值比较（双方都必须可解析为数值）。</li>
 * </ul>
 */
public enum ConditionOperator {
    EQ,
    NE,
    IN,
    NOT_IN,
    GT,
    GTE,
    LT,
    LTE;

    /** 是否为集合类比较（values 必须非空，允许多个值） */
    public boolean isCollection() {
        return this == IN || this == NOT_IN;
    }

    /** 是否为数值比较（双方必须能解析为数字） */
    public boolean isNumeric() {
        return this == GT || this == GTE || this == LT || this == LTE;
    }
}
