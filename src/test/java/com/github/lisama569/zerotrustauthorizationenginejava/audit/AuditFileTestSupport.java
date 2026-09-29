package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Decision;

/** 审计测试辅助：构造持久化文件用的 JSON 行 */
public final class AuditFileTestSupport {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AuditFileTestSupport() {
    }

    /** 伪造一条序列号与哈希都自说自话的记录行（模拟外部插入） */
    public static String forgedLine(long sequence, String subjectId) {
        AuditRecord r = new AuditRecord(sequence, "forged-" + sequence, 1L,
                subjectId, "read", "d", 1, "c", Decision.ALLOW, "r", "1", "",
                "FAKE-PREVIOUS", "FAKE-HASH");
        try {
            var n = MAPPER.createObjectNode();
            n.put("sequence", r.getSequence());
            n.put("auditId", r.getAuditId());
            n.put("timestamp", r.getTimestamp());
            n.put("subjectId", r.getSubjectId());
            n.put("action", r.getAction());
            n.put("resourceId", r.getResourceId());
            n.put("resourceSensitivity", r.getResourceSensitivity());
            n.put("contextSummary", r.getContextSummary());
            n.put("decision", r.getDecision().name());
            n.put("matchedRuleId", r.getMatchedRuleId());
            n.put("policyVersion", r.getPolicyVersion());
            n.put("attributeConditionBasis", r.getAttributeConditionBasis());
            n.put("previousHash", r.getPreviousHash());
            n.put("currentHash", r.getCurrentHash());
            return MAPPER.writeValueAsString(n);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
