package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;

import java.util.ArrayList;
import java.util.List;

/** 纯内存存储：重启即丢，仅供测试或显式禁用持久化时使用 */
public class InMemoryAuditStore implements AuditStore {

    private final List<AuditRecord> records = new ArrayList<>();

    @Override
    public synchronized StoredRecords readAll() {
        return new StoredRecords(new ArrayList<>(records), records.size(), false, "");
    }

    @Override
    public synchronized void append(AuditRecord record) {
        records.add(record);
    }

    @Override
    public synchronized void quarantineAndRewrite(List<AuditRecord> intactPrefix) {
        records.clear();
        records.addAll(intactPrefix);
    }

    @Override
    public void commitCheckpoint(int count, String lastHash) {
        // 纯内存存储无旁路检查点
    }

    @Override
    public String location() {
        return "in-memory";
    }
}
