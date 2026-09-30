package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditCheckpoint;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditFileTestSupport;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditIntegrityException;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLog;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.FileAuditStore;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditVerificationResult;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Decision;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 审计持久化与重启恢复测试：
 * - 重启后历史记录整体读回，哈希链复核仍通过；
 * - 本地文件被改过/插入/删除/截断，重放时能定位首个问题位置并隔离恢复；
 * - 恢复后新记录接在完好链尾，链重新完整。
 */
class AuditPersistenceTest {

    private static final Logger log = LoggerFactory.getLogger(AuditPersistenceTest.class);

    private AuditLog fileBackedLog(Path file) {
        return new AuditLog(new FileAuditStore(file));
    }

    @Test
    @DisplayName("重启后整体读回历史记录，链完整，verify 标记来自持久化")
    void replayAcrossRestart(@TempDir Path dir) {
        Path file = dir.resolve("audit.jsonl");
        AuditLog firstRun = fileBackedLog(file);
        for (int i = 0; i < 50; i++) {
            firstRun.append("alice", "read", "d" + i, i % 5 + 1,
                    "ctx", i % 2 == 0 ? Decision.ALLOW : Decision.DENY,
                    "rule", "1.1.0",
                    "clearanceLevel GTE 3 (actual=4, 满足)");
        }
        assertEquals(50, firstRun.size());

        // 模拟进程重启：新建 AuditLog，从同一文件重放
        AuditLog secondRun = fileBackedLog(file);
        var outcome = secondRun.loadFromPersistence();
        assertFalse(outcome.corrupted());
        assertEquals(50, secondRun.size());
        assertEquals(50, outcome.records().size());

        AuditVerificationResult v = secondRun.verify();
        assertTrue(v.isIntact(), v.getDetail());
        assertTrue(v.isLoadedFromPersistence());
        assertEquals(50, v.getReplayedCount());
        // 属性条件依据随记录持久化并读回
        assertTrue(secondRun.all().get(0).getAttributeConditionBasis().contains("clearanceLevel"));

        // 重启后继续追加，链接在历史链尾且连续
        AuditRecord continued = secondRun.append("bob", "read", "d99", 5,
                "ctx", Decision.ALLOW, "rule", "1.1.0", "");
        assertEquals(50, continued.getSequence());
        assertTrue(secondRun.verify().isIntact());
        log.info("重启重放 50 条并续写 seq={}，链完整", continued.getSequence());
    }

    @Test
    @DisplayName("文件中某条记录被改写 -> 重放定位被改序列号并隔离恢复")
    void tamperedContentDetectedOnReplay(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit.jsonl");
        AuditLog log1 = fileBackedLog(file);
        log1.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        log1.append("b", "read", "d", 1, "c", Decision.DENY, "r", "1");
        log1.append("c", "read", "d", 1, "c", Decision.ALLOW, "r", "1");

        List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
        lines.set(1, lines.get(1).replace("\"subjectId\":\"b\"", "\"subjectId\":\"mallory\""));
        Files.write(file, lines, StandardCharsets.UTF_8);

        AuditLog log2 = fileBackedLog(file);
        var outcome = log2.loadFromPersistence();
        assertTrue(outcome.corrupted());
        assertEquals(1L, outcome.brokenAtSequence());
        // 仅恢复前 1 条完好记录
        assertEquals(1, log2.size());
        log2.append("n", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        assertTrue(log2.verify().isIntact(), "恢复后续写链必须重新完整");
        assertTrue(Files.list(dir).anyMatch(p -> p.getFileName().toString().contains(".corrupt-")),
                "损坏原文件应被隔离");
        log.info("篡改内容在重放时被发现 seq={}", outcome.brokenAtSequence());
    }

    @Test
    @DisplayName("文件中插入伪造记录 -> 序列号/前驱校验失败并定位")
    void insertedRecordDetectedOnReplay(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit.jsonl");
        AuditLog log1 = fileBackedLog(file);
        log1.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        log1.append("b", "read", "d", 1, "c", Decision.DENY, "r", "1");

        // 在末尾插入一条序列号声称很大的伪造行（哈希链必断）
        String forged = AuditFileTestSupport.forgedLine(99L, "intruder");
        Files.writeString(file,
                Files.readString(file, StandardCharsets.UTF_8) + forged + "\n",
                StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.APPEND);

        AuditLog log2 = fileBackedLog(file);
        var outcome = log2.loadFromPersistence();
        assertTrue(outcome.corrupted());
        assertNotNull(outcome.brokenAtSequence());
        assertEquals(2, log2.size(), "伪造行之前的 2 条完好记录应被恢复");
        assertTrue(log2.verify().isIntact());
        log.info("插入伪造记录被发现 reportedSeq={}", outcome.brokenAtSequence());
    }

    @Test
    @DisplayName("文件中间一条被删除 -> 序列号断裂，定位到删除后的首个位置")
    void deletedRecordDetectedOnReplay(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit.jsonl");
        AuditLog log1 = fileBackedLog(file);
        log1.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        log1.append("b", "read", "d", 1, "c", Decision.DENY, "r", "1");
        log1.append("c", "read", "d", 1, "c", Decision.ALLOW, "r", "1");

        List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
        lines.remove(1);
        Files.write(file, lines, StandardCharsets.UTF_8);

        AuditLog log2 = fileBackedLog(file);
        var outcome = log2.loadFromPersistence();
        assertTrue(outcome.corrupted());
        assertEquals(2L, outcome.brokenAtSequence(), "原 seq=2 的记录现在序列号为 1，期望 2");
        assertEquals(1, log2.size());
        assertTrue(log2.verify().isIntact());
        log.info("删除记录被发现 seq={}", outcome.brokenAtSequence());
    }

    @Test
    @DisplayName("文件被截断（末尾半行）-> 识别为损坏，完好前缀恢复")
    void truncatedFileDetectedOnReplay(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit.jsonl");
        AuditLog log1 = fileBackedLog(file);
        for (int i = 0; i < 5; i++) {
            log1.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        }
        String content = Files.readString(file, StandardCharsets.UTF_8);
        // 截掉最后 40 个字符，末行变成无法解析的半行
        Files.writeString(file, content.substring(0, content.length() - 40),
                StandardCharsets.UTF_8);

        AuditLog log2 = fileBackedLog(file);
        var outcome = log2.loadFromPersistence();
        assertTrue(outcome.corrupted(), "截断必须被识别为损坏");
        assertEquals(4, log2.size(), "前 4 条完好记录恢复，第 5 条半行被丢弃");
        assertTrue(log2.verify().isIntact());
        assertNotNull(outcome.brokenAtSequence());
        log.info("截断被发现 recovered={} reportedSeq={}", log2.size(),
                outcome.brokenAtSequence());
    }

    /** 删掉文件末尾一整条完整记录（剩余前缀依然自洽，仅哈希链无法发现） */
    @Test
    @DisplayName("尾部删除 1 条完整记录 -> 识别损坏、定位缺失起点与缺失条数")
    void tailSingleDeletionDetectedOnReplay(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit.jsonl");
        AuditLog log1 = fileBackedLog(file);
        for (int i = 0; i < 6; i++) {
            log1.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        }

        List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
        assertEquals(6, lines.size());
        lines.remove(lines.size() - 1); // 整行删除最后一条 seq=5
        Files.write(file, lines, StandardCharsets.UTF_8);

        AuditLog log2 = fileBackedLog(file);
        var outcome = log2.loadFromPersistence();
        assertTrue(outcome.corrupted(), "尾部删除必须判定为损坏");
        assertFalse(outcome.unrecoverable());
        assertEquals(5L, outcome.brokenAtSequence(), "缺失起点必须定位到 seq=5");
        assertTrue(outcome.detail().contains("缺失 1 条"),
                "必须给出缺失规模，实际 detail=" + outcome.detail());
        assertTrue(outcome.detail().contains("seq=5"), "必须能定位缺失位置");
        assertEquals(5, log2.size(), "只恢复完好的前 5 条，残缺部分不得继续当历史");

        // 恢复后追加：新记录接在 seq=5，序号连续不重复，链完整
        AuditRecord continued = log2.append("b", "read", "d", 1, "c",
                Decision.DENY, "r", "1");
        assertEquals(5, continued.getSequence());
        AuditVerificationResult v = log2.verify();
        assertTrue(v.isIntact(), v.getDetail());
        assertTrue(v.isLoadCorrupted(), "verify 必须反映本次启动曾检出损坏");
        assertTrue(v.getRecoveryDetail().contains("尾部记录缺失"));
        assertTrue(Files.list(dir).anyMatch(p -> p.getFileName().toString()
                .contains(".corrupt-")), "残缺原文件必须隔离");

        // 再次重启：重建后的基线与文件一致，判定正常，可继续追加
        AuditLog log3 = fileBackedLog(file);
        var outcome3 = log3.loadFromPersistence();
        assertFalse(outcome3.corrupted(),
                "恢复并续写后再重启应判定正常: " + outcome3.detail());
        assertEquals(6, log3.size());
        AuditRecord next = log3.append("c", "read", "d", 1, "c",
                Decision.ALLOW, "r", "1");
        assertEquals(6, next.getSequence());
        assertTrue(log3.verify().isIntact());
        log.info("尾部删除 1 条被识别并恢复，缺失起点 seq={}", outcome.brokenAtSequence());
    }

    /** 连续删掉末尾多条完整记录 */
    @Test
    @DisplayName("尾部连续删除多条完整记录 -> 识别损坏、定位起点并报出缺失条数")
    void tailMultipleDeletionDetectedOnReplay(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit.jsonl");
        AuditLog log1 = fileBackedLog(file);
        for (int i = 0; i < 10; i++) {
            log1.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        }

        List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
        lines.subList(6, lines.size()).clear(); // 删除 seq=6,7,8,9 共 4 条
        Files.write(file, lines, StandardCharsets.UTF_8);

        AuditLog log2 = fileBackedLog(file);
        var outcome = log2.loadFromPersistence();
        assertTrue(outcome.corrupted(), "连续尾部删除必须判定为损坏");
        assertEquals(6L, outcome.brokenAtSequence(), "缺失起点为 seq=6");
        assertTrue(outcome.detail().contains("缺失 4 条"),
                "必须报出缺失 4 条，实际 detail=" + outcome.detail());
        assertTrue(outcome.detail().contains("seq=6"));
        assertEquals(6, log2.size());

        // 恢复后连续追加多条，序号连续不重复、链完整、记录不丢
        for (int i = 0; i < 5; i++) {
            AuditRecord r = log2.append("a", "read", "d", 1, "c",
                    Decision.ALLOW, "r", "1");
            assertEquals(6 + i, r.getSequence());
        }
        assertEquals(11, log2.size());
        assertTrue(log2.verify().isIntact(), "恢复后续写链必须完整");
        log.info("尾部连续删除 4 条被识别，缺失起点 seq={}", outcome.brokenAtSequence());
    }

    /** 已经产生过记录后，整份历史数据文件被删除（基线仍在） */
    @Test
    @DisplayName("产生记录后整份历史文件被删 -> 不可复核、拒绝从零续写，区别于首次使用")
    void wholeHistoryDeletionIsUnrecoverable(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit.jsonl");
        Path checkpoint = dir.resolve("audit.jsonl.checkpoint");
        AuditLog log1 = fileBackedLog(file);
        log1.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        log1.append("b", "read", "d", 1, "c", Decision.DENY, "r", "1");
        assertTrue(Files.exists(checkpoint), "首次写入后必须生成基线文件");

        // 模拟有人整份删除审计历史（基线保留）
        Files.delete(file);

        AuditLog log2 = fileBackedLog(file);
        var outcome = log2.loadFromPersistence();
        assertTrue(outcome.unrecoverable(), "整体丢失必须判定为不可恢复");
        assertTrue(outcome.corrupted());
        assertTrue(outcome.detail().contains("整体丢失"));
        assertTrue(log2.isUnrecoverable());
        assertEquals(0, log2.size());

        // 不能默默从零开始：追加必须被拒绝
        assertThrows(AuditIntegrityException.class, () -> log2.append(
                "x", "read", "d", 1, "c", Decision.ALLOW, "r", "1"));

        AuditVerificationResult v = log2.verify();
        assertFalse(v.isIntact(), "整体丢失绝不能报完整");
        assertTrue(v.isUnrecoverable());
        assertTrue(v.getRecoveryDetail().contains("整体丢失"));
        assertFalse(Files.exists(file), "判定不可恢复时不得自动补建空数据文件");

        // 对照：首次使用（数据与基线都不存在）应正常初始化并可追加
        Path fresh = dir.resolve("fresh-audit.jsonl");
        AuditLog firstUse = fileBackedLog(fresh);
        var freshOutcome = firstUse.loadFromPersistence();
        assertFalse(freshOutcome.corrupted());
        assertFalse(freshOutcome.unrecoverable());
        assertEquals(0, firstUse.size());
        AuditRecord first = firstUse.append("a", "read", "d", 1, "c",
                Decision.ALLOW, "r", "1");
        assertEquals(0, first.getSequence());
        assertTrue(firstUse.verify().isIntact());

        // 运维显式处置：清除/归档现场（基线也删掉）后重置 -> 按首次使用重建
        Files.deleteIfExists(checkpoint);
        var resetOutcome = log2.resetUnrecoverable();
        assertFalse(resetOutcome.unrecoverable(), "现场清除后重置应解除不可恢复");
        assertFalse(resetOutcome.corrupted());
        AuditRecord afterReset = log2.append("a", "read", "d", 1, "c",
                Decision.ALLOW, "r", "1");
        assertEquals(0, afterReset.getSequence(), "重置后从 seq=0 全新开始");
        assertTrue(log2.verify().isIntact());
        log.info("整份历史丢失判定不可恢复，显式处置后可重新初始化");
    }

    /** 首次使用（目录为空）：构造即重放，不应报损坏，也不应生成孤立基线 */
    @Test
    @DisplayName("全新目录首次启动 -> 空历史正常初始化，基线就绪")
    void firstRunOnEmptyDirectory(@TempDir Path dir) {
        Path file = dir.resolve("audit.jsonl");
        AuditLog log = fileBackedLog(file);
        var outcome = log.loadFromPersistence();
        assertFalse(outcome.corrupted());
        assertFalse(outcome.unrecoverable());
        assertTrue(Files.exists(dir.resolve("audit.jsonl.checkpoint")));
        AuditRecord r = log.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        assertEquals(0, r.getSequence());
        assertTrue(log.verify().isIntact());
    }

    /** 多轮正常重启：基线随追加持续推进，记录与序号跨重启连续不丢 */
    @Test
    @DisplayName("多轮正常重启：记录不丢、序号跨重启连续、始终判定完整")
    void multipleRestartsKeepContinuousSequence(@TempDir Path dir) {
        Path file = dir.resolve("audit.jsonl");
        int total = 0;
        for (int round = 0; round < 4; round++) {
            AuditLog log = fileBackedLog(file);
            var outcome = log.loadFromPersistence();
            assertFalse(outcome.corrupted(),
                    "第 " + round + " 轮重启不应损坏: " + outcome.detail());
            assertEquals(total, log.size());
            for (int i = 0; i < 7; i++) {
                AuditRecord r = log.append("a", "read", "d", 1, "c",
                        Decision.ALLOW, "r", "1");
                assertEquals(total + i, r.getSequence());
            }
            total += 7;
            assertTrue(log.verify().isIntact());
        }
        AuditLog finalRun = fileBackedLog(file);
        assertEquals(total, finalRun.loadFromPersistence().records().size());
        AuditRecord next = finalRun.append("a", "read", "d", 1, "c",
                Decision.ALLOW, "r", "1");
        assertEquals(total, next.getSequence());
        log.info("4 轮重启共 {} 条，序号连续完整", total + 1);
    }

    /** 模拟“记录已落盘但基线停在上一条”的崩溃窗口：下链哈希一致时补齐基线 */
    @Test
    @DisplayName("崩溃窗口（基线落后 1 条且哈希可对上）-> 正常追赶补齐，不判损坏")
    void crashWindowOneRecordAheadIsCaughtUp(@TempDir Path dir) {
        Path file = dir.resolve("audit.jsonl");
        Path checkpointFile = dir.resolve("audit.jsonl.checkpoint");
        AuditLog log1 = fileBackedLog(file);
        for (int i = 0; i < 4; i++) {
            log1.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        }
        // 手工把基线回退到 3 条（模拟第 4 条落盘后、基线更新前崩溃）
        AuditRecord third = log1.all().get(2);
        new AuditCheckpoint(checkpointFile).write(3, third.getCurrentHash());

        AuditLog log2 = fileBackedLog(file);
        var outcome = log2.loadFromPersistence();
        assertFalse(outcome.corrupted(),
                "基线仅落后 1 条且锚点哈希一致时应正常追赶: " + outcome.detail());
        assertEquals(4, log2.size());
        assertTrue(log2.verify().isIntact());
        // 基线已补齐：再次重启稳定判定正常
        AuditLog log3 = fileBackedLog(file);
        assertFalse(log3.loadFromPersistence().corrupted());
        assertEquals(4, log3.size());
        log.info("崩溃窗口追赶成功，4 条全部确认");
    }

    /** 基线落后超过 1 条（非崩溃可解释）-> 判损坏，按完好前缀隔离恢复 */
    @Test
    @DisplayName("数据领先基线超过 1 条 -> 判损坏并隔离前缀")
    void dataTooFarAheadOfCheckpointIsCorruption(@TempDir Path dir) {
        Path file = dir.resolve("audit.jsonl");
        Path checkpointFile = dir.resolve("audit.jsonl.checkpoint");
        AuditLog log1 = fileBackedLog(file);
        for (int i = 0; i < 5; i++) {
            log1.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        }
        // 基线回退到 2 条，与实际相差 3 条，超出崩溃窗口
        AuditRecord second = log1.all().get(1);
        new AuditCheckpoint(checkpointFile).write(2, second.getCurrentHash());

        AuditLog log2 = fileBackedLog(file);
        var outcome = log2.loadFromPersistence();
        assertTrue(outcome.corrupted(), "超出崩溃窗口的领先必须判损坏");
        assertEquals(5, log2.size(), "链完好则记录全部保留并隔离重建");
        assertTrue(log2.verify().isIntact());
        log.info("数据领先基线 3 条被识别为损坏并重建基线");
    }

    /** 老版本数据：只有数据文件、没有基线，链完好 -> 自举建立基线，行为不回归 */
    @Test
    @DisplayName("无基线的老数据文件且链完好 -> 自举基线，正常续写")
    void legacyDataWithoutCheckpointBootstraps(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit.jsonl");
        Path checkpointFile = dir.resolve("audit.jsonl.checkpoint");
        AuditLog log1 = fileBackedLog(file);
        log1.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        log1.append("b", "read", "d", 1, "c", Decision.DENY, "r", "1");
        // 模拟老版本现场：删除基线，仅留数据文件
        Files.delete(checkpointFile);

        AuditLog log2 = fileBackedLog(file);
        var outcome = log2.loadFromPersistence();
        assertFalse(outcome.corrupted(), "老数据升级不应判损坏: " + outcome.detail());
        assertEquals(2, log2.size());
        assertTrue(Files.exists(checkpointFile), "应自举重建基线");
        AuditRecord next = log2.append("c", "read", "d", 1, "c",
                Decision.ALLOW, "r", "1");
        assertEquals(2, next.getSequence());
        // 再重启：基线已就位，尾部删除从此可被识别
        AuditLog log3 = fileBackedLog(file);
        var afterBootstrap = log3.loadFromPersistence();
        assertFalse(afterBootstrap.corrupted());
        assertEquals(3, log3.size());
        log.info("老数据自举基线成功");
    }
}
