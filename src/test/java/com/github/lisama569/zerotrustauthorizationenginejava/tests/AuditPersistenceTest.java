package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLog;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditPersistenceException;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.FileAuditStore;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;
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
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 审计持久化与重启恢复测试：
 * - 重启后历史记录整体读回，哈希链复核通过，序列号延续不重复；
 * - 本地记录被篡改/插入/删除/截断，恢复时必须发现并指出位置；
 * - 持久化模式下并发写入不丢记录、不重号、链不断。
 */
class AuditPersistenceTest {

    private static final Logger log = LoggerFactory.getLogger(AuditPersistenceTest.class);

    @TempDir
    Path tempDir;

    private AuditLog fileBackedLog(String name) {
        Path dir = tempDir.resolve(name);
        FileAuditStore store = new FileAuditStore(
                dir.resolve("records.jsonl"), dir.resolve("checkpoint.json"));
        return new AuditLog(store);
    }

    private Path recordsFile(String name) {
        return tempDir.resolve(name).resolve("records.jsonl");
    }

    @Test
    @DisplayName("重启恢复：历史记录整体读回、链复核通过、序列号延续")
    void recoverAfterRestart() {
        AuditLog first = fileBackedLog("recover");
        for (int i = 0; i < 50; i++) {
            first.append("alice", "read", "doc" + i, 3, "ctx",
                    "evaluated=[department[EQ]]", Decision.ALLOW, "r1", "1.0.0");
        }
        assertTrue(first.verify().isIntact());

        // 模拟进程重启：用同一路径新建日志实例并恢复
        AuditLog second = fileBackedLog("recover");
        int recovered = second.recoverFromStore();
        assertEquals(50, recovered);
        assertTrue(second.verify().isIntact(), second.verify().getDetail());
        assertEquals(50, second.size());

        // 恢复后继续追加，序列号必须从 50 延续，不重复、不断链
        AuditRecord continued = second.append("bob", "read", "doc-x", 5, "ctx2",
                null, Decision.DENY, "r2", "1.0.0");
        assertEquals(50, continued.getSequence());
        assertTrue(second.verify().isIntact());

        // 再重启一次仍可整体读回
        AuditLog third = fileBackedLog("recover");
        assertEquals(51, third.recoverFromStore());
        assertTrue(third.verify().isIntact());
        log.info("两次重启恢复通过，最终记录数={}", third.size());
    }

    @Test
    @DisplayName("本地记录内容被篡改 -> 恢复复核失败并定位位置")
    void tamperedContentDetectedOnRecovery() throws Exception {
        AuditLog log1 = fileBackedLog("tamper");
        for (int i = 0; i < 5; i++) {
            log1.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        }
        Path records = recordsFile("tamper");
        List<String> lines = Files.readAllLines(records, StandardCharsets.UTF_8);
        String tampered = lines.get(2).replace("\"subjectId\":\"a\"", "\"subjectId\":\"mallory\"");
        lines.set(2, tampered);
        Files.write(records, lines, StandardCharsets.UTF_8);

        AuditLog log2 = fileBackedLog("tamper");
        AuditPersistenceException ex = assertThrows(AuditPersistenceException.class,
                log2::recoverFromStore);
        log.info("篡改检测 location={} message={}", ex.getLocation(), ex.getMessage());
        assertNotNull(ex.getLocation());
    }

    @Test
    @DisplayName("记录文件被截断（删掉尾部）-> 检查点记录数不符，指出截断位置")
    void truncationDetectedOnRecovery() throws Exception {
        AuditLog log1 = fileBackedLog("truncate");
        for (int i = 0; i < 10; i++) {
            log1.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        }
        Path records = recordsFile("truncate");
        List<String> lines = Files.readAllLines(records, StandardCharsets.UTF_8);
        Files.write(records, lines.subList(0, 7), StandardCharsets.UTF_8);

        AuditLog log2 = fileBackedLog("truncate");
        AuditPersistenceException ex = assertThrows(AuditPersistenceException.class,
                log2::recoverFromStore);
        log.info("截断检测 location={} message={}", ex.getLocation(), ex.getMessage());
        assertTrue(ex.getMessage().contains("截断") || ex.getMessage().contains("不一致"));
    }

    @Test
    @DisplayName("删除中间记录 -> 序列号不连续，指出问题位置")
    void deletionDetectedOnRecovery() throws Exception {
        AuditLog log1 = fileBackedLog("delete");
        for (int i = 0; i < 6; i++) {
            log1.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        }
        Path records = recordsFile("delete");
        List<String> mutated = new ArrayList<>(Files.readAllLines(records, StandardCharsets.UTF_8));
        mutated.remove(3);
        Files.write(records, mutated, StandardCharsets.UTF_8);

        AuditLog log2 = fileBackedLog("delete");
        AuditPersistenceException ex = assertThrows(AuditPersistenceException.class,
                log2::recoverFromStore);
        log.info("删除检测 location={} message={}", ex.getLocation(), ex.getMessage());
        assertNotNull(ex.getLocation());
    }

    @Test
    @DisplayName("插入无法解析的伪造行 -> 指出问题行号")
    void insertionDetectedOnRecovery() throws Exception {
        AuditLog log1 = fileBackedLog("insert");
        for (int i = 0; i < 4; i++) {
            log1.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        }
        Path records = recordsFile("insert");
        List<String> mutated = new ArrayList<>(Files.readAllLines(records, StandardCharsets.UTF_8));
        mutated.add(2, "{this is not valid json");
        Files.write(records, mutated, StandardCharsets.UTF_8);

        AuditLog log2 = fileBackedLog("insert");
        AuditPersistenceException ex = assertThrows(AuditPersistenceException.class,
                log2::recoverFromStore);
        log.info("插入检测 location={} message={}", ex.getLocation(), ex.getMessage());
        assertTrue(ex.getLocation().contains("line=3"));
    }

    @Test
    @DisplayName("伪造记录含未知字段 -> 反序列化拒绝，恢复失败")
    void unknownFieldInPersistedRecordDetected() throws Exception {
        AuditLog log1 = fileBackedLog("unknown-field");
        log1.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        Path records = recordsFile("unknown-field");
        List<String> lines = new ArrayList<>(Files.readAllLines(records, StandardCharsets.UTF_8));
        AuditRecord rec = log1.all().get(0);
        String fake = new ObjectMapper().writeValueAsString(rec)
                .replace("\"subjectId\":\"a\"", "\"subjectId\":\"a\",\"backdoor\":true")
                .replace("\"sequence\":0", "\"sequence\":1")
                .replace("\"auditId\":\"" + rec.getAuditId() + "\"",
                        "\"auditId\":\"fake-id\"");
        lines.add(fake);
        Files.write(records, lines, StandardCharsets.UTF_8);

        AuditLog log2 = fileBackedLog("unknown-field");
        AuditPersistenceException ex = assertThrows(AuditPersistenceException.class,
                log2::recoverFromStore);
        log.info("未知字段伪造记录检测 location={} message={}", ex.getLocation(), ex.getMessage());
        assertNotNull(ex.getLocation());
    }

    @Test
    @DisplayName("持久化模式并发 16×250=4000 条：不丢、不重号、链完整，重启后仍可复核")
    void concurrentPersistentAppendNoLoss() throws Exception {
        AuditLog audit = fileBackedLog("concurrent");
        int threads = 16;
        int perThread = 250;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        ConcurrentLinkedQueue<Long> sequences = new ConcurrentLinkedQueue<>();

        for (int t = 0; t < threads; t++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        AuditRecord r = audit.append("s", "a", "r", 1, "c",
                                Decision.ALLOW, "rule", "1.0.0");
                        sequences.add(r.getSequence());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(90, TimeUnit.SECONDS));
        pool.shutdown();

        assertEquals(threads * perThread, audit.size());
        List<Long> sorted = sequences.stream().sorted().collect(Collectors.toList());
        for (int i = 0; i < sorted.size(); i++) {
            assertEquals(i, sorted.get(i), "序列号必须连续不重复");
        }
        assertTrue(audit.verify().isIntact(), audit.verify().getDetail());

        // 重启后 4000 条一条不少且链完整
        AuditLog reopened = fileBackedLog("concurrent");
        assertEquals(threads * perThread, reopened.recoverFromStore());
        assertTrue(reopened.verify().isIntact(), reopened.verify().getDetail());
        log.info("持久化并发追加 + 重启复核通过 count={}", reopened.size());
    }
}
