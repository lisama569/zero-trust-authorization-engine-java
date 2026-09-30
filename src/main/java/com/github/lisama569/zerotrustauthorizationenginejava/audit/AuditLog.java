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
 * 链外基线：JSONL 旁还有一份检查点（记录数 + 末条哈希）。哈希链前缀自洽的两类破坏
 * 仅靠链无法发现——尾部整段删除、曾有记录后整份历史文件被删；基线使前者被识别为
 * 可定位的损坏（隔离前缀后续写），后者被识别为不可恢复（{@link #isUnrecoverable()}，
 * 拒绝追加，等待运维显式处置）。首次使用（数据与基线均不存在）正常初始化。
 */
public class AuditLog {

    private static final Logger log = LoggerFactory.getLogger(AuditLog.class);

    private final Object lock = new Object();
    private final List<AuditRecord> records = new ArrayList<>();
    private final AuditStore store;
    private AuditLoadOutcome loadOutcome;
    /** 历史整体丢失等无法复核的状态：拒绝一切追加，直到显式重置 */
    private boolean poisoned;

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
            if (poisoned) {
                throw new AuditIntegrityException("审计历史无法复核（历史整体丢失），"
                        + "已拒绝追加以避免覆盖/分叉；请先由运维显式处置后重置："
                        + store.location());
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
     * 首个不通过的位置即断裂点。检测到任何问题（坏行/截断、行数不一致、
     * 尾部缺失、基线异常），隔离原文件并用最长完好前缀重建。
     * 若基线显示曾有记录而历史文件整体缺失，则判为不可恢复：不隔离、不重建、
     * 不接受续写，标记 poisoned 并返回 unrecoverable 结果。
     */
    public AuditLoadOutcome loadFromPersistence() {
        synchronized (lock) {
            poisoned = false;
            StoredRecords stored = store.readAll();
            List<AuditRecord> loaded = stored.records();
            StoredRecords.CheckpointState anchor = stored.anchor() == null
                    ? StoredRecords.CheckpointState.absent() : stored.anchor();

            // 1) 历史整体丢失：基线存在且曾确认过记录，但数据文件不存在
            if (anchor.present() && anchor.valid() && anchor.expectedCount() > 0
                    && !anchor.dataExists()) {
                poisoned = true;
                String detail = "审计历史文件整体丢失：基线记录应有 "
                        + anchor.expectedCount() + " 条，但数据文件不存在；"
                        + "无法复核也不能从零续写";
                log.error("{} location={}", detail, store.location());
                records.clear();
                this.loadOutcome = new AuditLoadOutcome(List.of(), true, null,
                        detail, stored.rawLineCount(), true);
                return loadOutcome;
            }

            // 2) 从创世重算哈希链，取最长完好前缀
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

            // 3) 对照链外基线：识别尾部整段删除 / 崩溃追赶 / 基线异常
            boolean needsAnchorRewrite = false;
            if (anchor.present() && anchor.valid() && anchor.dataExists()) {
                int expected = anchor.expectedCount();
                if (intact.size() < expected) {
                    // 剩余完好记录少于基线：尾部整段删除（或内部删除同时丢尾）。
                    // 纯尾部删除时剩余前缀完全自洽，链检测发现不了，由基线给出缺失起点；
                    // 链内部已在更靠后位置报告断裂（如中间删除）时保留链的定位，
                    // 只追加缺失规模信息。
                    corrupted = true;
                    long missingFrom = intact.size();
                    long missingCount = expected - (long) intact.size();
                    String missingNote = "基线记录应有 " + expected + " 条，实际完好 "
                            + intact.size() + " 条，缺失 " + missingCount
                            + " 条（尾部缺失自 seq=" + missingFrom + " 起），"
                            + "不能把残缺历史当作正常历史续写";
                    if (brokenAt == null) {
                        brokenAt = missingFrom;
                        detail = "检测到尾部记录缺失：" + missingNote;
                    } else {
                        brokenAt = Math.max(brokenAt, missingFrom);
                        detail = detail + "；同时" + missingNote;
                    }
                } else if (intact.size() > expected) {
                    // 数据领先基线：正常崩溃（最后一次写后未及更新基线）至多领先 1 条，
                    // 且基线锚定的末条哈希必须仍能对上
                    AuditRecord anchoredLast = intact.get(Math.max(0, expected - 1));
                    String anchoredHash = expected == 0
                            ? AuditHasher.GENESIS_HASH : anchoredLast.getCurrentHash();
                    if (intact.size() - expected > 1 || !anchoredHash.equals(anchor.lastHash())) {
                        corrupted = true;
                        if (brokenAt == null) {
                            brokenAt = (long) expected;
                        }
                        detail = "持久化记录数（" + intact.size()
                                + "）超出基线记录数（" + expected
                                + "）或基线末条哈希不匹配，文件可能被外部追加/替换";
                    } else {
                        // 崩溃后重放：领先的 1 条链哈希自洽，确认追赶基线
                        needsAnchorRewrite = true;
                        log.info("检测到上次退出前最后一条记录已落盘但基线未及推进，"
                                + "重放确认 {} 条并补齐基线", intact.size());
                    }
                } else if (!intact.isEmpty()) {
                    // 条数一致：末条哈希也必须一致，否则基线指向的历史已被替换
                    String actualLast = intact.get(intact.size() - 1).getCurrentHash();
                    if (!actualLast.equals(anchor.lastHash())) {
                        corrupted = true;
                        if (brokenAt == null) {
                            brokenAt = (long) (intact.size() - 1);
                        }
                        detail = "末条记录哈希与基线不一致，历史文件可能被整体替换";
                    }
                }
            } else if (anchor.present() && !anchor.valid()) {
                // 基线自身损坏：无法据其识别尾部删除/整体丢失，按损坏处理；
                // 链前缀完好时接受并重建基线，但明确告警
                corrupted = true;
                if (brokenAt == null) {
                    brokenAt = (long) intact.size();
                }
                detail = "审计基线（checkpoint）无法通过校验：" + anchor.detail()
                        + "；已按哈希链完好前缀恢复并重建基线，但建议人工核对";
                needsAnchorRewrite = true;
            } else if (!anchor.present() && anchor.dataExists() && !intact.isEmpty()
                    && intact.size() == loaded.size() && !stored.malformed()) {
                // 老版本数据升级：无基线但自带一条完好哈希链，自举建立基线
                needsAnchorRewrite = true;
                log.info("未发现审计基线，文件哈希链完好，按 {} 条记录自举建立基线",
                        intact.size());
            } else if (!anchor.present() && !anchor.dataExists()) {
                // 首次使用（或不可恢复后清除了现场）：建立空数据与空基线
                store.ensureInitialized();
            }

            if (corrupted) {
                store.quarantineAndRewrite(intact);
                log.warn("审计持久化文件损坏，首个问题位置 seq={}，恢复完好记录 {} 条，原始行数 {}：{}",
                        brokenAt, intact.size(), stored.rawLineCount(), detail);
            } else if (needsAnchorRewrite) {
                String lastHash = intact.isEmpty()
                        ? AuditHasher.GENESIS_HASH
                        : intact.get(intact.size() - 1).getCurrentHash();
                store.commitCheckpoint(intact.size(), lastHash);
            }
            records.clear();
            records.addAll(intact);
            this.loadOutcome = new AuditLoadOutcome(List.copyOf(intact), corrupted,
                    brokenAt, detail, stored.rawLineCount(), false);
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
     * 是否处于不可恢复状态（历史整体丢失，已拒绝追加）。
     * 处置方式：运维确认后删除数据文件与基线文件（或归档备份），
     * 再调用本方法/重启完成“首次使用”式重新初始化。
     */
    public boolean isUnrecoverable() {
        synchronized (lock) {
            return poisoned;
        }
    }

    /**
     * 运维显式处置完现场（数据与基线均已清除）后调用：
     * 解除不可恢复状态并重新加载，按首次使用建立空基线。
     * 若现场未清除干净（基线仍声称有历史），将保持不可恢复。
     */
    public AuditLoadOutcome resetUnrecoverable() {
        synchronized (lock) {
            if (!poisoned) {
                return loadOutcome;
            }
            return loadFromPersistence();
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
        boolean loadCorrupted = false;
        boolean unrecoverable = false;
        synchronized (lock) {
            unrecoverable = poisoned;
            if (loadOutcome != null) {
                replayed = true;
                replayedCount = loadOutcome.records().size();
                loadCorrupted = loadOutcome.corrupted();
                if (loadOutcome.unrecoverable()) {
                    recovery = "启动重放判定历史整体丢失，无法复核：" + loadOutcome.detail()
                            + "；已拒绝追加，需运维清除/归档数据与基线后重置";
                } else if (loadOutcome.corrupted()) {
                    recovery = "启动重放时检测到损坏 seq=" + loadOutcome.brokenAtSequence()
                            + "：" + loadOutcome.detail() + "；已隔离原文件并恢复 "
                            + loadOutcome.records().size() + " 条完好记录";
                }
            }
        }
        boolean overallIntact = chain.isIntact() && !unrecoverable;
        String overallDetail = unrecoverable
                ? "审计历史整体丢失，无法复核："
                        + (loadOutcome == null ? "" : loadOutcome.detail())
                : chain.getDetail();
        return new AuditVerificationResult(overallIntact, chain.getRecordCount(),
                chain.getBrokenAtSequence(), overallDetail,
                replayed, replayedCount, recovery, loadCorrupted, unrecoverable);
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
