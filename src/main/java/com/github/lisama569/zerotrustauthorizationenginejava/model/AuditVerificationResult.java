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
    /** 历史整体丢失且尚未显式恢复：此时 intact=false，追加被拒绝 */
    private final boolean historyLost;

    public AuditVerificationResult(boolean intact, int recordCount, Long brokenAtSequence,
                                   String detail) {
        this(intact, recordCount, brokenAtSequence, detail, false, 0, "", false);
    }

    public AuditVerificationResult(boolean intact, int recordCount, Long brokenAtSequence,
                                   String detail, boolean loadedFromPersistence,
                                   int replayedCount, String recoveryDetail) {
        this(intact, recordCount, brokenAtSequence, detail, loadedFromPersistence,
                replayedCount, recoveryDetail, false);
    }

    public AuditVerificationResult(boolean intact, int recordCount, Long brokenAtSequence,
                                   String detail, boolean loadedFromPersistence,
                                   int replayedCount, String recoveryDetail,
                                   boolean historyLost) {
        this.intact = intact;
        this.recordCount = recordCount;
        this.brokenAtSequence = brokenAtSequence;
        this.detail = detail;
        this.loadedFromPersistence = loadedFromPersistence;
        this.replayedCount = replayedCount;
        this.recoveryDetail = recoveryDetail == null ? "" : recoveryDetail;
        this.historyLost = historyLost;
    }

    public boolean isIntact() { return intact; }
    public int getRecordCount() { return recordCount; }
    public Long getBrokenAtSequence() { return brokenAtSequence; }
    public String getDetail() { return detail; }
    public boolean isLoadedFromPersistence() { return loadedFromPersistence; }
    public int getReplayedCount() { return replayedCount; }
    public String getRecoveryDetail() { return recoveryDetail; }
    public boolean isHistoryLost() { return historyLost; }
}
