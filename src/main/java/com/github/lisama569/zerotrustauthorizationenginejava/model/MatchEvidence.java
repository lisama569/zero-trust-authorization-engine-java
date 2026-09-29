package com.github.lisama569.zerotrustauthorizationenginejava.model;

import java.util.List;

/**
 * 规则命中/受阻的结构化证据，供审计复盘。
 *
 * <p>记录规则在主体属性条件维度上实际核对了哪些条件（仅记录条件键与比较方式，
 * 不记录主体属性的敏感值），以及缺失/受阻的属性键。</p>
 */
public final class MatchEvidence {

    /** 实际参与核对的属性条件描述，例如 "department[EQ]" */
    private final List<String> evaluatedConditions;
    /** 规则要求但主体未提供的属性键（信息缺失） */
    private final List<String> missingAttributes;

    public MatchEvidence(List<String> evaluatedConditions, List<String> missingAttributes) {
        this.evaluatedConditions = evaluatedConditions;
        this.missingAttributes = missingAttributes;
    }

    public List<String> getEvaluatedConditions() { return evaluatedConditions; }
    public List<String> getMissingAttributes() { return missingAttributes; }
}
