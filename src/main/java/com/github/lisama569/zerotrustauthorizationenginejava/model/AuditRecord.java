package com.github.lisama569.zerotrustauthorizationenginejava.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 一条不可篡改的审计记录。
 * previousHash + currentHash 构成哈希链：任一记录被篡改或缺失，
 * 后续校验即可发现。
 *
 * <p>{@code conditionEvidence} 记录本条判定实际核对了哪些主体属性条件，
 * 便于事后复盘（仅含条件键与比较方式，不含主体属性敏感值）。</p>
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
    private final String conditionEvidence;
    private final Decision decision;
    private final String matchedRuleId;
    private final String policyVersion;
    private final String previousHash;
    private final String currentHash;

    @JsonCreator
    public AuditRecord(@JsonProperty("sequence") long sequence,
                       @JsonProperty("auditId") String auditId,
                       @JsonProperty("timestamp") long timestamp,
                       @JsonProperty("subjectId") String subjectId,
                       @JsonProperty("action") String action,
                       @JsonProperty("resourceId") String resourceId,
                       @JsonProperty("resourceSensitivity") Integer resourceSensitivity,
                       @JsonProperty("contextSummary") String contextSummary,
                       @JsonProperty("conditionEvidence") String conditionEvidence,
                       @JsonProperty("decision") Decision decision,
                       @JsonProperty("matchedRuleId") String matchedRuleId,
                       @JsonProperty("policyVersion") String policyVersion,
                       @JsonProperty("previousHash") String previousHash,
                       @JsonProperty("currentHash") String currentHash) {
        this.sequence = sequence;
        this.auditId = auditId;
        this.timestamp = timestamp;
        this.subjectId = subjectId;
        this.action = action;
        this.resourceId = resourceId;
        this.resourceSensitivity = resourceSensitivity;
        this.contextSummary = contextSummary;
        this.conditionEvidence = conditionEvidence;
        this.decision = decision;
        this.matchedRuleId = matchedRuleId;
        this.policyVersion = policyVersion;
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
    public String getConditionEvidence() { return conditionEvidence; }
    public Decision getDecision() { return decision; }
    public String getMatchedRuleId() { return matchedRuleId; }
    public String getPolicyVersion() { return policyVersion; }
    public String getPreviousHash() { return previousHash; }
    public String getCurrentHash() { return currentHash; }
}
