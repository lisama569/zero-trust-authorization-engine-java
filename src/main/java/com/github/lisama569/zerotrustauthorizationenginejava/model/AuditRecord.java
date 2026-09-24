package com.github.lisama569.zerotrustauthorizationenginejava.model;

/**
 * 审计记录（与 audit 包的序列化逻辑配合）：
 * seq 单调序号；prevHash/recordHash 构成哈希链；
 * payloadHash 覆盖关键上下文摘要。
 */
public record AuditRecord(
        long seq,
        long timestamp,
        String requestId,
        String subjectId,
        String resourceId,
        String action,
        String contextDigest,
        String version,
        DecisionOutcome outcome,
        String matchedRuleId,
        String reason,
        String prevHash,
        String recordHash
) {
}
