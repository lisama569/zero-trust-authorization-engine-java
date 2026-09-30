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
    /** 本次启动重放是否检测到损坏（含尾部删除等已隔离恢复的情况） */
    private final boolean loadCorrupted;
    /** 历史整体丢失等无法复核的状态（拒绝追加，需运维处置） */
    private final boolean unrecoverable;

    public AuditVerificationResult(boolean intact, int recordCount, Long brokenAtSequence,
                                   String detail) {
        this(intact, recordCount, brokenAtSequence, detail, false, 0, "", false, false);
    }

    public AuditVerificationResult(boolean intact, int recordCount, Long brokenAtSequence,
                                   String detail, boolean loadedFromPersistence,
                                   int replayedCount, String recoveryDetail) {
        this(intact, recordCount, brokenAtSequence, detail, loadedFromPersistence,
                replayedCount, recoveryDetail, false, false);
    }

    public AuditVerificationResult(boolean intact, int recordCount, Long brokenAtSequence,
                                   String detail, boolean loadedFromPersistence,
                                   int replayedCount, String recoveryDetail,
                                   boolean loadCorrupted, boolean unrecoverable) {
        this.intact = intact;
        this.recordCount = recordCount;
        this.brokenAtSequence = brokenAtSequence;
        this.detail = detail;
        this.loadedFromPersistence = loadedFromPersistence;
        this.replayedCount = replayedCount;
        this.recoveryDetail = recoveryDetail == null ? "" : recoveryDetail;
        this.loadCorrupted = loadCorrupted;
        this.unrecoverable = unrecoverable;
    }

    public boolean isIntact() { return intact; }
    public int getRecordCount() { return recordCount; }
    public Long getBrokenAtSequence() { return brokenAtSequence; }
    public String getDetail() { return detail; }
    public boolean isLoadedFromPersistence() { return loadedFromPersistence; }
    public int getReplayedCount() { return replayedCount; }
    public String getRecoveryDetail() { return recoveryDetail; }
    public boolean isLoadCorrupted() { return loadCorrupted; }
    public boolean isUnrecoverable() { return unrecoverable; }
}
