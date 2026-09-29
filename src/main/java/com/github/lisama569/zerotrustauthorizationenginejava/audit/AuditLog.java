package com.github.lisama569.zerotrustauthorizationenginejava.audit;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditVerificationResult;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Decision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 追加式哈希链审计日志（带本地持久化与重启重放）。
 *
 * 并发保证：append 全程在同一把锁内完成“取末条哈希 -> 分配序列号 -> 落盘 -> 入内存”，
 * 先落盘后入内存，保证已返回给调用方的记录不会丢失、序列号连续不重复、链不分叉。
 *
 * 重启恢复：{@link #loadFromPersistence()} 读取存储并从创世开始重算哈希链，
 * 接受最长完好前缀；文件被改过/插入/删除/截断均可定位首个断裂位置，
 * 损坏原文件被隔离，仅用完好前缀重建后继续追加。
 */
public class AuditLog {

    private static final Logger log = LoggerFactory.getLogger(AuditLog.class);

    private final Object lock = new Object();
    private final List<AuditRecord> records = new ArrayList<>();
    private final AuditStore store;
    private AuditLoadOutcome loadOutcome;

    public AuditLog() {
        this(new InMemoryAuditStore());
    }

    public AuditLog(AuditStore store) {
        this.store = store;
    }

    public AuditRecord append(String subjectId, String action, String resourceId,
                              Integer resourceSensitivity, String contextSummary,
                              Decision decision, String matchedRuleId, String policyVersion) {
        return append(subjectId, action, resourceId, resourceSensitivity, contextSummary,
                decision, matchedRuleId, policyVersion, "");
    }

    public AuditRecord append(String subjectId, String action, String resourceId,
                              Integer resourceSensitivity, String contextSummary,
                              Decision decision, String matchedRuleId, String policyVersion,
                              String attributeConditionBasis) {
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
                    contextSummary, decision, matchedRuleId, policyVersion,
                    attributeConditionBasis == null ? "" : attributeConditionBasis,
                    previousHash, "");
            String currentHash = AuditHasher.computeHash(pending);
            AuditRecord sealed = new AuditRecord(
                    pending.getSequence(), pending.getAuditId(), pending.getTimestamp(),
                    subjectId, action, resourceId, resourceSensitivity,
                    contextSummary, decision, matchedRuleId, policyVersion,
                    pending.getAttributeConditionBasis(),
                    previousHash, currentHash);
            // 先持久化，落盘成功后才入内存：异常时不会出现“内存有序号但文件没有”
            store.append(sealed);
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
     * 启动时从持久化存储重放历史记录并复核哈希链。
     * 从创世起逐条验证：序列号连续、前驱指针一致、内容哈希一致；
     * 首个不通过的位置即断裂点。检测到任何问题（含坏行/截断、行数不一致），
     * 隔离原文件并用最长完好前缀重建。
     */
    public AuditLoadOutcome loadFromPersistence() {
        synchronized (lock) {
            StoredRecords stored = store.readAll();
            List<AuditRecord> loaded = stored.records();

            List<AuditRecord> intact = new ArrayList<>();
            String expectedPrevious = AuditHasher.GENESIS_HASH;
            Long brokenAt = null;
            String detail = "";
            for (AuditRecord r : loaded) {
                long expectedSeq = intact.size();
                if (r.getSequence() != expectedSeq) {
                    brokenAt = r.getSequence();
                    detail = "序列号不连续（期望 " + expectedSeq + "），记录可能被删除、插入或重排";
                    break;
                }
                if (!expectedPrevious.equals(r.getPreviousHash())) {
                    brokenAt = r.getSequence();
                    detail = "前驱哈希不匹配，前序记录可能被篡改或删除";
                    break;
                }
                if (!AuditHasher.computeHash(r).equals(r.getCurrentHash())) {
                    brokenAt = r.getSequence();
                    detail = "记录哈希不一致，记录内容被篡改";
                    break;
                }
                intact.add(r);
                expectedPrevious = r.getCurrentHash();
            }

            boolean corrupted = brokenAt != null || stored.malformed()
                    || stored.rawLineCount() != loaded.size()
                    || stored.rawLineCount() != intact.size();
            if (corrupted && brokenAt == null && intact.size() == loaded.size()) {
                // 哈希链本身完好，但文件里有坏行（截断）或行数对不上
                brokenAt = (long) intact.size();
                detail = stored.malformed() ? stored.detail()
                        : "持久化行数与可解析记录数不一致，文件可能被截断";
                if (detail == null || detail.isBlank()) {
                    detail = "持久化文件存在无法恢复的额外内容（截断/插入）";
                }
            }

            if (corrupted) {
                store.quarantineAndRewrite(intact);
                log.warn("审计持久化文件损坏，首个问题位置 seq={}，恢复完好记录 {} 条，原始行数 {}：{}",
                        brokenAt, intact.size(), stored.rawLineCount(), detail);
            }
            records.clear();
            records.addAll(intact);
            this.loadOutcome = new AuditLoadOutcome(List.copyOf(intact), corrupted,
                    brokenAt, detail, stored.rawLineCount());
            log.info("审计日志重放完成 location={} 完好记录={} 损坏={} 原始行数={}",
                    store.location(), intact.size(), corrupted, stored.rawLineCount());
            return loadOutcome;
        }
    }

    /** 启动加载结果（未加载过为 null） */
    public AuditLoadOutcome loadOutcome() {
        synchronized (lock) {
            return loadOutcome;
        }
    }

    /**
     * 校验整条哈希链：
     * 1) 序列号连续；2) 前驱指针正确；3) 每条 currentHash 重算一致。
     * 同时附带启动持久化重放信息（是否从持久化恢复、重放条数、恢复细节）。
     */
    public AuditVerificationResult verify() {
        List<AuditRecord> snapshot = all();
        AuditVerificationResult chain = verifyChain(snapshot);
        boolean replayed = false;
        int replayedCount = 0;
        String recovery = "";
        synchronized (lock) {
            if (loadOutcome != null) {
                replayed = true;
                replayedCount = loadOutcome.records().size();
                if (loadOutcome.corrupted()) {
                    recovery = "启动重放时检测到损坏 seq=" + loadOutcome.brokenAtSequence()
                            + "：" + loadOutcome.detail() + "；已隔离原文件并恢复 "
                            + loadOutcome.records().size() + " 条完好记录";
                }
            }
        }
        return new AuditVerificationResult(chain.isIntact(), chain.getRecordCount(),
                chain.getBrokenAtSequence(), chain.getDetail(),
                replayed, replayedCount, recovery);
    }

    private AuditVerificationResult verifyChain(List<AuditRecord> snapshot) {
        String expectedPrevious = AuditHasher.GENESIS_HASH;
        for (int i = 0; i < snapshot.size(); i++) {
            AuditRecord r = snapshot.get(i);
            if (r.getSequence() != i) {
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
}
