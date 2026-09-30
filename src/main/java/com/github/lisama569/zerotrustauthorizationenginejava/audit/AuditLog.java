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
 *
 * 两类哈希链自检发现不了的破坏由带外封签水位（条数 + 末条哈希）兜底：
 * - 末尾一整行/连续几整行被删：剩余链仍然自洽，但条数少于封签水位，
 *   判损坏并定位到缺失起点（完好前缀长度即保留下来的最后一个连续序号），
 *   残缺部分不会被当作正常历史继续往后接；
 * - 数据文件在产生过记录后整体丢失：读到空历史但封签显示曾有记录，
 *   判“历史整体丢失”（与首次使用无历史区分），进入不可复核的锁定状态，
 *   拒绝一切追加，直到 {@link #recoverAfterHistoryLoss()} 显式确认并重置。
 */
public class AuditLog {

    private static final Logger log = LoggerFactory.getLogger(AuditLog.class);

    private final Object lock = new Object();
    private final List<AuditRecord> records = new ArrayList<>();
    private final AuditStore store;
    private AuditLoadOutcome loadOutcome;
    /** 历史整体丢失后的锁定标志：true 时拒绝追加，必须显式恢复 */
    private boolean historyLostLocked;
    /** 历史整体丢失时封签确认的条数（供恢复说明使用） */
    private long committedCountAtLoss;
    /** 显式恢复重置后留存的说明（仅当前进程内可见，证据文件已隔离） */
    private String resetNotice = "";

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
            if (historyLostLocked) {
                throw new AuditHistoryUnavailableException(
                        "审计历史整体丢失且尚未复核确认，已拒绝追加新记录；"
                                + "请先通过 /api/audit/recover-history 显式恢复，不能静默从零续写");
            }
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
     * 首个不通过的位置即断裂点。检测到任何问题（含坏行/截断、行数不一致、
     * 与带外封签水位不符的尾部删除/末条替换），隔离原文件并用最长完好前缀重建。
     *
     * 封签显示此前有记录、但数据一条都读不出来时判为“历史整体丢失”：
     * 不隔离、不重建、不追加，保持证据原样并进入锁定，等待显式恢复。
     */
    public AuditLoadOutcome loadFromPersistence() {
        synchronized (lock) {
            historyLostLocked = false;
            resetNotice = "";
            committedCountAtLoss = 0;
            StoredRecords stored = store.readAll();
            List<AuditRecord> loaded = stored.records();

            // 历史整体丢失：封签确认曾有记录，数据文件却整体缺失/清空/不可解析。
            // 与首次使用（无封签、无数据）严格区分：这里必须报错并锁定，不能当空历史。
            if (stored.historyExists() && loaded.isEmpty()) {
                String lostDetail = "审计历史整体丢失：带外封签确认此前已有 "
                        + stored.committedCount() + " 条记录（末条哈希 "
                        + stored.committedLastHash() + "），但数据文件 "
                        + store.location() + " 中当前没有任何可解析记录；"
                        + "无法复核，已拒绝追加，需显式恢复后才能重新开始记录";
                records.clear();
                historyLostLocked = true;
                committedCountAtLoss = stored.committedCount();
                this.loadOutcome = new AuditLoadOutcome(List.of(), true, 0L,
                        lostDetail, stored.rawLineCount(), true);
                log.error("{}", lostDetail);
                return loadOutcome;
            }

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

            boolean chainOrLineBroken = brokenAt != null || stored.malformed()
                    || stored.rawLineCount() != loaded.size()
                    || stored.rawLineCount() != intact.size();
            if (chainOrLineBroken && brokenAt == null && intact.size() == loaded.size()) {
                // 哈希链本身完好，但文件里有坏行（截断）或行数对不上
                brokenAt = (long) intact.size();
                detail = stored.malformed() ? stored.detail()
                        : "持久化行数与可解析记录数不一致，文件可能被截断";
                if (detail == null || detail.isBlank()) {
                    detail = "持久化文件存在无法恢复的额外内容（截断/插入）";
                }
            }

            // 哈希链自检通过后，再与带外封签水位比对：
            // 链自洽但条数少于封签 => 末尾整行被删（删 1 条或连续多条同样适用）
            boolean tailDeleted = !chainOrLineBroken
                    && stored.committedCount() > intact.size();
            if (tailDeleted) {
                brokenAt = (long) intact.size();
                detail = "审计记录尾部缺失：封签确认应有 " + stored.committedCount()
                        + " 条，实际只剩 " + intact.size() + " 条；自 seq="
                        + intact.size() + " 起（含）到 seq="
                        + (stored.committedCount() - 1) + " 的连续记录被整行删除，"
                        + "缺失位置之后不得当作正常历史继续追加";
            }
            // 条数一致但末条哈希对不上 => 最后一条被替换/重算
            boolean lastRecordSwapped = !chainOrLineBroken && !tailDeleted
                    && stored.historyExists()
                    && stored.committedCount() == intact.size() && !intact.isEmpty()
                    && !stored.committedLastHash().equals(
                            intact.get(intact.size() - 1).getCurrentHash());
            if (lastRecordSwapped) {
                brokenAt = (long) (intact.size() - 1);
                detail = "末条记录哈希与封签不一致，最后一条记录可能被替换或重算（位置 seq="
                        + brokenAt + "）";
            }

            boolean corrupted = chainOrLineBroken || tailDeleted || lastRecordSwapped;
            if (corrupted) {
                // 隔离原文件，仅用最长完好前缀重建并把封签水位收回到完好前缀
                store.quarantineAndRewrite(intact);
                log.warn("审计持久化文件损坏，首个问题位置 seq={}，恢复完好记录 {} 条，"
                                + "封签条数 {}，原始行数 {}：{}",
                        brokenAt, intact.size(), stored.committedCount(),
                        stored.rawLineCount(), detail);
            } else if (!intact.isEmpty()) {
                // 健康历史：旧版本文件首次加载（无封签）或上次崩溃在两盘之间
                // （数据多、封签旧）时，把封签补齐到当前完好水位
                boolean checkpointStale = stored.historyExists()
                        && stored.committedCount() < intact.size();
                if (checkpointStale || !stored.historyExists()) {
                    store.commitWatermark(intact);
                    if (checkpointStale) {
                        log.info("封签水位落后于完好数据（{} < {}），已补齐",
                                stored.committedCount(), intact.size());
                    } else {
                        log.info("检测到无封签的历史文件，已按完好链补建封签水位 {} 条",
                                intact.size());
                    }
                }
            }

            records.clear();
            records.addAll(intact);
            this.loadOutcome = new AuditLoadOutcome(List.copyOf(intact), corrupted,
                    brokenAt, detail, stored.rawLineCount());
            log.info("审计日志重放完成 location={} 完好记录={} 损坏={} 封签条数={} 原始行数={}",
                    store.location(), intact.size(), corrupted,
                    stored.committedCount(), stored.rawLineCount());
            return loadOutcome;
        }
    }

    /**
     * 历史整体丢失后的显式恢复：隔离残留数据与旧封签作为证据（*.lost-时间戳），
     * 重置为空历史并建立全新初始封签，之后记录从 seq=0 重新开始。
     * 必须在锁定状态下显式调用——不会在启动时自动“当作没发生过”。
     */
    public AuditLoadOutcome recoverAfterHistoryLoss() {
        synchronized (lock) {
            if (!historyLostLocked) {
                throw new AuditHistoryUnavailableException(
                        "当前没有待恢复的“审计历史整体丢失”状态，无需恢复");
            }
            long lostCount = committedCountAtLoss;
            store.resetForFreshHistory();
            records.clear();
            historyLostLocked = false;
            committedCountAtLoss = 0;
            resetNotice = "此前带外封签确认存在 " + lostCount
                    + " 条审计记录，但数据整体缺失/不可读；已由运维显式确认重置，"
                    + "残留与旧封签被隔离为 *.lost-<时间戳> 证据文件，新历史自 seq=0 重新计数";
            this.loadOutcome = new AuditLoadOutcome(List.of(), false, null,
                    "历史整体丢失后已显式重置", 0, false);
            log.warn("审计历史整体丢失已显式恢复，确认丢失 {} 条，新历史从空开始", lostCount);
            return loadOutcome;
        }
    }

    /** 是否处于历史整体丢失后的锁定状态（此时追加会被拒绝） */
    public boolean isHistoryLost() {
        synchronized (lock) {
            return historyLostLocked;
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
     * 历史整体丢失锁定时直接给出 intact=false 且 historyLost=true，
     * 不会把“空内存链”误报为完整。
     */
    public AuditVerificationResult verify() {
        List<AuditRecord> snapshot = all();
        AuditVerificationResult chain = verifyChain(snapshot);
        boolean replayed = false;
        int replayedCount = 0;
        String recovery = "";
        boolean historyLost;
        synchronized (lock) {
            historyLost = historyLostLocked;
            if (historyLostLocked) {
                recovery = loadOutcome == null ? "" : loadOutcome.detail();
            } else if (!resetNotice.isBlank()) {
                recovery = resetNotice;
            }
            if (loadOutcome != null) {
                replayed = true;
                replayedCount = loadOutcome.records().size();
                if (loadOutcome.corrupted() && !historyLostLocked) {
                    recovery = "启动重放时检测到损坏 seq=" + loadOutcome.brokenAtSequence()
                            + "：" + loadOutcome.detail() + "；已隔离原文件并恢复 "
                            + loadOutcome.records().size() + " 条完好记录";
                }
            }
        }
        boolean intact = chain.isIntact() && !historyLost;
        Long brokenAt = historyLost ? Long.valueOf(0L) : chain.getBrokenAtSequence();
        String detail = historyLost
                ? "审计历史整体丢失，无法复核（已拒绝追加，需显式恢复）"
                : chain.getDetail();
        return new AuditVerificationResult(intact, chain.getRecordCount(),
                brokenAt, detail, replayed, replayedCount, recovery, historyLost);
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
