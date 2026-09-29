package com.github.lisama569.zerotrustauthorizationenginejava.model;

/**
 * 一条不可篡改的审计记录。
 * previousHash + currentHash 构成哈希链：任一记录被篡改或缺失，
 * 后续校验即可发现。
 */
public final class AuditRecord {
    private final long sequence;
    private final String auditId;
    private final long timestamp;
    private final String subjectId;
    private final String action;
    private final String resourceId;
    private final Integer resourceSensitivity;
    private final String contextSummary;
    private final Decision decision;
    private final String matchedRuleId;
    private final String policyVersion;
    private final String attributeConditionBasis;
    private final String previousHash;
    private final String currentHash;

    /** 旧签名：不含属性条件依据（兼容历史调用点） */
    public AuditRecord(long sequence, String auditId, long timestamp, String subjectId,
                       String action, String resourceId, Integer resourceSensitivity,
                       String contextSummary, Decision decision, String matchedRuleId,
                       String policyVersion, String previousHash, String currentHash) {
        this(sequence, auditId, timestamp, subjectId, action, resourceId, resourceSensitivity,
                contextSummary, decision, matchedRuleId, policyVersion, "",
                previousHash, currentHash);
    }

    public AuditRecord(long sequence, String auditId, long timestamp, String subjectId,
                       String action, String resourceId, Integer resourceSensitivity,
                       String contextSummary, Decision decision, String matchedRuleId,
                       String policyVersion, String attributeConditionBasis,
                       String previousHash, String currentHash) {
        this.sequence = sequence;
        this.auditId = auditId;
        this.timestamp = timestamp;
        this.subjectId = subjectId;
        this.action = action;
        this.resourceId = resourceId;
        this.resourceSensitivity = resourceSensitivity;
        this.contextSummary = contextSummary;
        this.decision = decision;
        this.matchedRuleId = matchedRuleId;
        this.policyVersion = policyVersion;
        this.attributeConditionBasis = attributeConditionBasis;
        this.previousHash = previousHash;
        this.currentHash = currentHash;
    }

    public long getSequence() { return sequence; }
    public String getAuditId() { return auditId; }
    public long getTimestamp() { return timestamp; }
    public String getSubjectId() { return subjectId; }
    public String getAction() { return action; }
    public String getResourceId() { return resourceId; }
    public Integer getResourceSensitivity() { return resourceSensitivity; }
    public String getContextSummary() { return contextSummary; }
    public Decision getDecision() { return decision; }
    public String getMatchedRuleId() { return matchedRuleId; }
    public String getPolicyVersion() { return policyVersion; }
    public String getAttributeConditionBasis() { return attributeConditionBasis; }
    public String getPreviousHash() { return previousHash; }
    public String getCurrentHash() { return currentHash; }
}
