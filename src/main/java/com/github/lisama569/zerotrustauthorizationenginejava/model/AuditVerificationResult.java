package com.github.lisama569.zerotrustauthorizationenginejava.model;

/** 审计链完整性校验结果 */
public final class AuditVerificationResult {
    private final boolean intact;
    private final int recordCount;
    private final Long brokenAtSequence;
    private final String detail;
    private final boolean loadedFromPersistence;
    private final int replayedCount;
    private final String recoveryDetail;

    public AuditVerificationResult(boolean intact, int recordCount, Long brokenAtSequence,
                                   String detail) {
        this(intact, recordCount, brokenAtSequence, detail, false, 0, "");
    }

    public AuditVerificationResult(boolean intact, int recordCount, Long brokenAtSequence,
                                   String detail, boolean loadedFromPersistence,
                                   int replayedCount, String recoveryDetail) {
        this.intact = intact;
        this.recordCount = recordCount;
        this.brokenAtSequence = brokenAtSequence;
        this.detail = detail;
        this.loadedFromPersistence = loadedFromPersistence;
        this.replayedCount = replayedCount;
        this.recoveryDetail = recoveryDetail == null ? "" : recoveryDetail;
    }

    public boolean isIntact() { return intact; }
    public int getRecordCount() { return recordCount; }
    public Long getBrokenAtSequence() { return brokenAtSequence; }
    public String getDetail() { return detail; }
    public boolean isLoadedFromPersistence() { return loadedFromPersistence; }
    public int getReplayedCount() { return replayedCount; }
    public String getRecoveryDetail() { return recoveryDetail; }
}
