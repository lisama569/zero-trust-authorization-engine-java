package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;

import java.util.ArrayList;
import java.util.List;

/**
 * 不落盘的内存存储（骨架，后续填充）。仅供不需要重启恢复的单元测试使用。
 */
public class InMemoryAuditStore implements AuditStore {

    private final List<AuditRecord> records = new ArrayList<>();

    @Override
    public synchronized void appendRecord(AuditRecord record) {
        records.add(record);
    }

    @Override
    public synchronized AuditRecovery recover() {
        return new AuditRecovery(new ArrayList<>(records));
    }

    @Override
    public synchronized void checkpoint(int recordCount, String lastHash) {
        // 内存模式无需检查点
    }
}
