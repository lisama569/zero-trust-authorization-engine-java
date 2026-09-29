package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLog;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.FileAuditStore;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Decision;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 并发写入 + 持久化联合测试：
 * 数千条并发追加落盘不丢记录、序列号不重复，重启读回后仍连续、链完整。
 */
class AuditConcurrentPersistenceTest {

    private static final Logger log =
            LoggerFactory.getLogger(AuditConcurrentPersistenceTest.class);

    @Test
    @DisplayName("12 线程 x 400 条并发落盘后重启：4800 条全部读回且链完整")
    void concurrentWritesSurviveRestart(@TempDir Path dir) throws InterruptedException {
        Path file = dir.resolve("concurrent-audit.jsonl");
        AuditLog audit = new AuditLog(new FileAuditStore(file));

        int threads = 12;
        int perThread = 400;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        ConcurrentLinkedQueue<Long> sequences = new ConcurrentLinkedQueue<>();

        for (int t = 0; t < threads; t++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        AuditRecord rec = audit.append("s", "a", "r", 1, "c",
                                Decision.ALLOW, "rule", "1.1.0",
                                "clearanceLevel GTE 3 (actual=4, 满足)");
                        sequences.add(rec.getSequence());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(60, TimeUnit.SECONDS));
        pool.shutdown();

        assertEquals(threads * perThread, audit.size());
        var sorted = sequences.stream().sorted().collect(Collectors.toList());
        for (int i = 0; i < sorted.size(); i++) {
            assertEquals(i, sorted.get(i), "序列号必须连续不重复");
        }

        // 模拟重启：从同一文件完整读回
        AuditLog restarted = new AuditLog(new FileAuditStore(file));
        var outcome = restarted.loadFromPersistence();
        assertFalse(outcome.corrupted(), "并发落盘后文件不应损坏: " + outcome.detail());
        assertEquals(threads * perThread, restarted.size(), "重启后记录一条都不能少");
        assertTrue(restarted.verify().isIntact(), "重启后哈希链必须完整");
        assertTrue(restarted.all().get(threads * perThread - 1)
                .getAttributeConditionBasis().contains("clearanceLevel"),
                "属性条件依据应随每条记录持久化");
        log.info("并发落盘 {} 条，重启后全部读回，链完整", restarted.size());
    }
}
