package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditVerificationResult;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Decision;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 追加式哈希链审计日志。
 *
 * 并发保证：append 全程在同一把锁内完成“取末条哈希 -> 分配序列号 -> 入链 -> 落盘”，
 * 因此并发压力下序列号连续不重复、不丢记录、链不会分叉。
 * 读取走快照拷贝，与写入互不阻塞。
 *
 * 持久性：构造时注入 {@link AuditStore} 时，每条记录在返回前落盘；
 * 进程重启后通过 {@link #recoverFromStore()} 把历史记录整体读回并复核。
 *
 * 完整性：每条记录 currentHash = SHA-256(previousHash | 业务字段)，
 * 任何记录被篡改、插入、删除、截断或重排，verify() 都能定位到断裂位置。
 */
public class AuditLog {

    private final Object lock = new Object();
    private final List<AuditRecord> records = new ArrayList<>();
    private final AuditStore store;

    /** 纯内存日志（不需要重启恢复的单元测试使用） */
    public AuditLog() {
        this(new InMemoryAuditStore());
    }

    /** 持久化日志：使用给定存储，重启后可恢复 */
    public AuditLog(AuditStore store) {
        this.store = store;
    }

    /**
     * 启动恢复：从存储读回全部历史记录，重算整条哈希链复核后装入内存。
     * 本地记录被改过/插入/删除/截断/无法解析 -> AuditPersistenceException（含位置）。
     *
     * @return 恢复的记录条数
     */
    public int recoverFromStore() {
        AuditRecovery recovery = store.recover();
        List<AuditRecord> recovered = recovery.getRecords();
        synchronized (lock) {
            if (!records.isEmpty()) {
                throw new AuditPersistenceException("audit-log",
                        "内存中已有审计记录，禁止重复恢复");
            }
            AuditVerificationResult chain = verifyList(recovered);
            if (!chain.isIntact()) {
                throw new AuditPersistenceException(
                        "seq=" + chain.getBrokenAtSequence(),
                        "恢复的审计哈希链复核失败: " + chain.getDetail());
            }
            records.addAll(recovered);
            return records.size();
        }
    }

    private static AuditVerificationResult verifyList(List<AuditRecord> snapshot) {
        String expectedPrevious = AuditHasher.GENESIS_HASH;
        for (AuditRecord r : snapshot) {
            if (r.getSequence() < 0 || snapshot.indexOf(r) != r.getSequence()) {
                return new AuditVerificationResult(false, snapshot.size(), r.getSequence(),
                        "序列号不连续，记录可能缺失或被重排");
            }
            if (!expectedPrevious.equals(r.getPreviousHash())) {
                return new AuditVerificationResult(false, snapshot.size(), r.getSequence(),
                        "前驱哈希不匹配，前序记录可能被篡改或删除");
            }
            String recomputed = AuditHasher.computeHash(r);
            if (!recomputed.equals(r.getCurrentHash())) {
                return new AuditVerificationResult(false, snapshot.size(), r.getSequence(),
                        "记录哈希不一致，记录内容被篡改");
            }
            expectedPrevious = r.getCurrentHash();
        }
        return new AuditVerificationResult(true, snapshot.size(), null, "审计链完整");
    }

    public AuditRecord append(String subjectId, String action, String resourceId,
                              Integer resourceSensitivity, String contextSummary,
                              Decision decision, String matchedRuleId, String policyVersion) {
        return append(subjectId, action, resourceId, resourceSensitivity,
                contextSummary, null, decision, matchedRuleId, policyVersion);
    }

    public AuditRecord append(String subjectId, String action, String resourceId,
                              Integer resourceSensitivity, String contextSummary,
                              String conditionEvidence,
                              Decision decision, String matchedRuleId, String policyVersion) {
        synchronized (lock) {
            long sequence = records.size();
            String previousHash = records.isEmpty()
                    ? AuditHasher.GENESIS_HASH
                    : records.get(records.size() - 1).getCurrentHash();
            AuditRecord pending = new AuditRecord(
                    sequence,
                    UUID.randomUUID().toString(),
                    System.currentTimeMillis(),
                    subjectId, action, resourceId, resourceSensitivity,
                    contextSummary, conditionEvidence, decision, matchedRuleId, policyVersion,
                    previousHash, "");
            String currentHash = AuditHasher.computeHash(pending);
            AuditRecord sealed = new AuditRecord(
                    pending.getSequence(), pending.getAuditId(), pending.getTimestamp(),
                    subjectId, action, resourceId, resourceSensitivity,
                    contextSummary, conditionEvidence, decision, matchedRuleId, policyVersion,
                    previousHash, currentHash);
            // 先落盘记录再更新检查点，全部在同一把锁内：
            // 并发下序列号连续不重复，且崩溃重启可复核出任何半截写入
            store.appendRecord(sealed);
            store.checkpoint(records.size() + 1, currentHash);
            records.add(sealed);
            return sealed;
        }
    }

    /** 只读快照 */
    public List<AuditRecord> all() {
        synchronized (lock) {
            return new ArrayList<>(records);
        }
    }

    public int size() {
        synchronized (lock) {
            return records.size();
        }
    }

    /**
     * 校验整条哈希链：
     * 1) 序列号连续；2) 前驱指针正确；3) 每条 currentHash 重算一致。
     */
    public AuditVerificationResult verify() {
        return verifyList(all());
    }
}
