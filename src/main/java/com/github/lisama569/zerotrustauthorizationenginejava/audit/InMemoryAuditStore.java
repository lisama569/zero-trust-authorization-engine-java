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
    public void commitWatermark(List<AuditRecord> intactPrefix) {
        // 纯内存存储没有带外封签，水位随内存列表天然一致，无需动作
    }

    @Override
    public synchronized void resetForFreshHistory() {
        records.clear();
    }

    @Override
    public String location() {
        return "in-memory";
    }
}
