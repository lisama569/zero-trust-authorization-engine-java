package com.github.lisama569.zerotrustauthorizationenginejava.model;

/** 审计链完整性校验结果 */
public final class AuditVerificationResult {
    private final boolean intact;
    private final int recordCount;
    private final Long brokenAtSequence;
    private final String detail;

    public AuditVerificationResult(boolean intact, int recordCount, Long brokenAtSequence, String detail) {
        this.intact = intact;
        this.recordCount = recordCount;
        this.brokenAtSequence = brokenAtSequence;
        this.detail = detail;
    }

    public boolean isIntact() { return intact; }
    public int getRecordCount() { return recordCount; }
    public Long getBrokenAtSequence() { return brokenAtSequence; }
    public String getDetail() { return detail; }
}
