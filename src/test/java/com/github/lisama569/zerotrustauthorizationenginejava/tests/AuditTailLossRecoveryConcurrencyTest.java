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
 * 尾部缺失被识别并隔离恢复后，多线程并发续写的可靠性：
 * 已恢复的完好记录不丢，新记录序列号在完好前缀之上连续不重复，
 * 再重启读回一条不少、链完整。
 */
class AuditTailLossRecoveryConcurrencyTest {

    private static final Logger log =
            LoggerFactory.getLogger(AuditTailLossRecoveryConcurrencyTest.class);

    @Test
    @DisplayName("尾部删 3 条恢复后，8 线程并发续写 + 再重启：序号连续、不丢不重")
    void concurrentAppendAfterTailRecovery(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit-tail-recover.jsonl");

        AuditLog first = new AuditLog(new FileAuditStore(file));
        for (int i = 0; i < 30; i++) {
            first.append("s", "read", "d" + i, 1, "c", Decision.ALLOW, "rule", "1.1.0",
                    "clearanceLevel GTE 3 (actual=4, 满足)");
        }

        List<String> lines = new ArrayList<>(Files.readAllLines(file, StandardCharsets.UTF_8));
        lines.subList(27, lines.size()).clear(); // 手工删掉末尾 seq=27,28,29
        Files.write(file, lines, StandardCharsets.UTF_8);

        AuditLog recovered = new AuditLog(new FileAuditStore(file));
        var outcome = recovered.loadFromPersistence();
        assertTrue(outcome.corrupted());
        assertEquals(27L, outcome.brokenAtSequence());
        assertEquals(27, recovered.size());

        int threads = 8;
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
                        AuditRecord r = recovered.append("s", "read", "d", 1, "c",
                                Decision.ALLOW, "rule", "1.1.0", "");
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
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();

        int total = 27 + threads * perThread;
        assertEquals(total, recovered.size(), "恢复前缀 + 并发续写一条不能少");
        List<Long> sorted = sequences.stream().sorted().collect(Collectors.toList());
        assertEquals(threads * perThread, sorted.size());
        for (int i = 0; i < sorted.size(); i++) {
            assertEquals(27L + i, sorted.get(i), "续写序号必须在完好前缀之上连续不重复");
        }
        assertTrue(recovered.verify().isIntact(), "并发续写后链必须完整");

        // 再重启：封签与数据一致，全部读回，不再报损坏
        AuditLog restarted = new AuditLog(new FileAuditStore(file));
        var again = restarted.loadFromPersistence();
        assertFalse(again.corrupted(), "恢复后重启不应再报损坏: " + again.detail());
        assertEquals(total, restarted.size());
        assertTrue(restarted.verify().isIntact());
        log.info("尾部缺失恢复后并发续写 {} 条并重启读回，序号连续链完整", total);
    }
}
