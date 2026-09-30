package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditFileTestSupport;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditHistoryUnavailableException;
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

    /** 生成 n 条记录并完成一轮正常运行（含封签落盘） */
    private AuditLog seedRuns(Path file, int n) {
        AuditLog first = fileBackedLog(file);
        for (int i = 0; i < n; i++) {
            first.append("u" + i, "read", "d" + i, i % 5 + 1, "ctx",
                    i % 2 == 0 ? Decision.ALLOW : Decision.DENY, "rule", "1.1.0",
                    "clearanceLevel GTE 3 (actual=4, 满足)");
        }
        assertEquals(n, first.size());
        return first;
    }

    @Test
    @DisplayName("删掉末尾一整行 -> 封签发现尾部缺失，定位缺失起点，残缺不续写")
    void tailOneLineDeletedDetectedOnReplay(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit-tail-one.jsonl");
        seedRuns(file, 10);

        List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
        assertEquals(10, lines.size());
        lines.remove(lines.size() - 1); // 手工删掉最后一条整行
        Files.write(file, lines, StandardCharsets.UTF_8);

        AuditLog log2 = fileBackedLog(file);
        var outcome = log2.loadFromPersistence();
        assertTrue(outcome.corrupted(), "尾部删一整行必须判损坏，不能把残缺当正常历史");
        assertEquals(9L, outcome.brokenAtSequence(), "缺失起点应定位到 seq=9");
        assertEquals(9, log2.size(), "只保留前 9 条完好记录");
        String detail = outcome.detail();
        assertTrue(detail.contains("尾部缺失") && detail.contains("10") && detail.contains("9"),
                "详情应给出应有/实有条数与缺失区间: " + detail);
        assertTrue(log2.verify().getRecoveryDetail().contains("seq=9"),
                "verify 的复核结果应带出定位信息");

        // 残缺部分不得当作正常历史：新记录只能接在完好链尾 seq=9
        AuditRecord continued = log2.append("new", "read", "d", 1, "c",
                Decision.ALLOW, "r", "1.1.0", "");
        assertEquals(9, continued.getSequence());
        assertEquals(10, log2.size());
        assertTrue(log2.verify().isIntact(), "恢复后续写哈希链必须重新完整");
        // 损坏原文件被隔离
        assertTrue(Files.list(dir).anyMatch(p -> p.getFileName().toString()
                .matches("audit-tail-one\\.jsonl\\.corrupt-\\d+")));
        log.info("尾部删 1 条被发现 brokenAt={} 续写 seq={}", outcome.brokenAtSequence(),
                continued.getSequence());
    }

    @Test
    @DisplayName("连续删掉末尾多条整行 -> 封签发现尾部缺失，区间定位准确")
    void tailMultipleLinesDeletedDetectedOnReplay(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit-tail-many.jsonl");
        seedRuns(file, 12);

        List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
        lines.subList(7, lines.size()).clear(); // 手工连续删掉 seq=7..11 共 5 条
        Files.write(file, lines, StandardCharsets.UTF_8);

        AuditLog log2 = fileBackedLog(file);
        var outcome = log2.loadFromPersistence();
        assertTrue(outcome.corrupted());
        assertEquals(7L, outcome.brokenAtSequence(), "缺失起点应定位到保留完好前缀长度 7");
        assertEquals(7, log2.size());
        assertTrue(outcome.detail().contains("seq=7") && outcome.detail().contains("seq=11"),
                "详情应给出缺失区间 seq=7 到 seq=11: " + outcome.detail());

        AuditRecord continued = log2.append("new", "read", "d", 1, "c",
                Decision.ALLOW, "r", "1.1.0", "");
        assertEquals(7, continued.getSequence(), "续写从完好前缀尾部 seq=7 开始，不使用旧序号");
        assertTrue(log2.verify().isIntact());
        log.info("尾部连续删 5 条被发现 brokenAt={} detail={}",
                outcome.brokenAtSequence(), outcome.detail());
    }

    @Test
    @DisplayName("产生过记录后整份历史文件被删 -> 报无法复核并锁定，与首次使用区分")
    void wholeHistoryDeletedIsNotFreshStart(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit-lost.jsonl");
        seedRuns(file, 6);
        Path checkpoint = dir.resolve("audit-lost.jsonl.checkpoint.json");
        assertTrue(Files.exists(checkpoint), "运行后应存在带外封签");

        // 模拟“整份本地审计历史文件被删掉”：只删数据文件，封签仍在
        Files.delete(file);

        AuditLog log2 = fileBackedLog(file);
        var outcome = log2.loadFromPersistence();
        assertTrue(outcome.corrupted());
        assertTrue(outcome.historyLost(), "必须与首次使用区分，标记为历史整体丢失");
        assertEquals(0, log2.size());
        assertTrue(outcome.detail().contains("整体丢失") && outcome.detail().contains("6"),
                "详情应说明此前确认条数: " + outcome.detail());

        AuditVerificationResult v = log2.verify();
        assertFalse(v.isIntact(), "空内存链不能被误报为完整");
        assertTrue(v.isHistoryLost());

        // 锁定状态下拒绝追加，不能默默从零继续
        assertThrows(AuditHistoryUnavailableException.class, () -> log2.append(
                "mallory", "read", "d", 1, "c", Decision.ALLOW, "r", "1.1.0", ""));
        assertTrue(log2.isHistoryLost());
        assertEquals(0, log2.size(), "被拒绝的追加不得留下任何记录");
        assertTrue(Files.notExists(file) || Files.readString(file, StandardCharsets.UTF_8).isBlank(),
                "锁定期间不应擅自重建数据文件掩盖丢失事实");
        log.info("整份历史删除被识别为无法复核: {}", outcome.detail());
    }

    @Test
    @DisplayName("首次使用（无数据无封签）-> 按空历史正常初始化，不判丢失")
    void firstUseWithNoFilesInitializesCleanly(@TempDir Path dir) {
        Path file = dir.resolve("brand-new/audit.jsonl");

        AuditLog firstRun = fileBackedLog(file);
        var outcome = firstRun.loadFromPersistence();
        assertFalse(outcome.corrupted());
        assertFalse(outcome.historyLost());
        assertEquals(0, firstRun.size());
        assertTrue(firstRun.verify().isIntact());
        assertFalse(firstRun.isHistoryLost());

        // 首次使用可以正常从零开始追加
        AuditRecord r = firstRun.append("alice", "read", "d1", 3, "c",
                Decision.ALLOW, "rule", "1.1.0", "");
        assertEquals(0, r.getSequence());
        assertTrue(firstRun.verify().isIntact());

        // 再重启：有封签有数据，正常复核
        AuditLog secondRun = fileBackedLog(file);
        var again = secondRun.loadFromPersistence();
        assertFalse(again.corrupted());
        assertFalse(again.historyLost());
        assertEquals(1, secondRun.size());
        log.info("首次使用正常初始化并可追加，重启复核通过");
    }

    @Test
    @DisplayName("历史整体丢失显式恢复后 -> 证据隔离，从空重新开始且序号连续不重复")
    void recoverAfterWholeHistoryLossThenAppend(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit-recover.jsonl");
        seedRuns(file, 8);
        Files.delete(file);

        AuditLog restarted = fileBackedLog(file);
        var lost = restarted.loadFromPersistence();
        assertTrue(lost.historyLost());
        assertThrows(AuditHistoryUnavailableException.class, () -> restarted.append(
                "x", "read", "d", 1, "c", Decision.ALLOW, "r", "1.1.0", ""));

        var recovered = restarted.recoverAfterHistoryLoss();
        assertFalse(recovered.corrupted());
        assertFalse(restarted.isHistoryLost());
        assertEquals(0, restarted.size());
        // 旧封签被隔离为证据，新初始封签已建立
        assertTrue(Files.list(dir).anyMatch(p -> p.getFileName().toString()
                .matches("audit-recover\\.jsonl\\.checkpoint\\.json\\.lost-\\d+")),
                "旧封签应被隔离为 *.lost-* 证据文件");

        AuditRecord first = restarted.append("alice", "read", "d", 1, "c",
                Decision.ALLOW, "r", "1.1.0", "");
        assertEquals(0, first.getSequence(), "新历史从 seq=0 重新计数");
        AuditRecord second = restarted.append("bob", "read", "d", 1, "c",
                Decision.DENY, "r", "1.1.0", "");
        assertEquals(1, second.getSequence(), "新历史序号连续不重复");
        assertTrue(restarted.verify().isIntact());

        // 恢复后再重启：不再误报丢失，记录读回
        AuditLog nextRun = fileBackedLog(file);
        var next = nextRun.loadFromPersistence();
        assertFalse(next.corrupted());
        assertFalse(next.historyLost());
        assertEquals(2, nextRun.size());
        assertTrue(nextRun.verify().isIntact());
        log.info("历史丢失恢复后重新追加并重启复核通过");
    }

    @Test
    @DisplayName("封签随每次追加更新 -> 正常重启水位一致，不产生误报")
    void checkpointKeepsUpAcrossNormalRestart(@TempDir Path dir) {
        Path file = dir.resolve("audit-cp.jsonl");
        seedRuns(file, 20);

        AuditLog restarted = fileBackedLog(file);
        var outcome = restarted.loadFromPersistence();
        assertFalse(outcome.corrupted(), "封签水位一致时正常重启不应误报损坏: "
                + outcome.detail());
        assertEquals(20, restarted.size());
        assertEquals(20, restarted.append("z", "read", "d", 1, "c",
                Decision.ALLOW, "r", "1.1.0", "").getSequence());
        assertTrue(restarted.verify().isIntact());
        log.info("封签水位正常重启复核通过 count=20");
    }
}
