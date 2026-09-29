package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * 审计记录 SHA-256 哈希链工具。
 * currentHash = SHA-256(previousHash | 规范化业务字段)，
 * 任意字段被篡改或记录被删除/重排，链校验都会失败。
 */
public final class AuditHasher {

    /** 创世记录的前驱哈希（固定常量） */
    public static final String GENESIS_HASH = "GENESIS";

    private AuditHasher() {
    }

    public static String hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] raw = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(raw);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * 生成记录的规范化载荷（不含 currentHash 自身），
     * 字段以 '|' 分隔，null 以空串表示，保证确定性。
     */
    public static String canonicalPayload(AuditRecord r) {
        return String.join("|",
                Long.toString(r.getSequence()),
                nz(r.getAuditId()),
                Long.toString(r.getTimestamp()),
                nz(r.getSubjectId()),
                nz(r.getAction()),
                nz(r.getResourceId()),
                r.getResourceSensitivity() == null ? "" : r.getResourceSensitivity().toString(),
                nz(r.getContextSummary()),
                r.getDecision() == null ? "" : r.getDecision().name(),
                nz(r.getMatchedRuleId()),
                nz(r.getPolicyVersion()),
                nz(r.getAttributeConditionBasis()),
                nz(r.getPreviousHash()));
    }

    /** 基于前驱哈希与业务字段计算当前哈希 */
    public static String computeHash(AuditRecord r) {
        return hash(r.getPreviousHash() + "|" + canonicalPayload(r));
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
