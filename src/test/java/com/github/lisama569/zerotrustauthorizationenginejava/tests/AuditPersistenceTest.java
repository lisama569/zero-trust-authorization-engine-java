package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditFileTestSupport;
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
}
