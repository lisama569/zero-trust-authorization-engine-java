package com.github.lisama569.zerotrustauthorizationenginejava.model;

/**
 * 授权评估对外结果。decision 可区分五类结论；
 * 内部异常细节不穿透，只保留安全的 reason 描述。
 */
public final class EvaluationResult {
    private final Decision decision;
    private final String policyVersion;
    private final String matchedRuleId;
    private final String reason;
    private final String auditId;

    public EvaluationResult(Decision decision, String policyVersion, String matchedRuleId,
                            String reason, String auditId) {
        this.decision = decision;
        this.policyVersion = policyVersion;
        this.matchedRuleId = matchedRuleId;
        this.reason = reason;
        this.auditId = auditId;
    }

    public Decision getDecision() { return decision; }
    public String getPolicyVersion() { return policyVersion; }
    public String getMatchedRuleId() { return matchedRuleId; }
    public String getReason() { return reason; }
    public String getAuditId() { return auditId; }
}
