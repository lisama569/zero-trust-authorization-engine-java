package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;

import java.util.List;

/** 启动恢复结果：从持久化存储读回的记录链 */
public final class AuditRecovery {

    private final List<AuditRecord> records;

    public AuditRecovery(List<AuditRecord> records) {
        this.records = records;
    }

    public List<AuditRecord> getRecords() {
        return records;
    }
}
