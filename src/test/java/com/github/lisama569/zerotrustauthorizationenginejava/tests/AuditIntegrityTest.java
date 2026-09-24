package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLogger;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditVerification;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AccessRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.DecisionOutcome;
import com.github.lisama569.zerotrustauthorizationenginejava.model.DecisionResult;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EnvironmentContext;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Resource;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Subject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 审计哈希链完整性、篡改检测、并发不丢记录测试。 */
class AuditIntegrityTest {

    private static final Logger log = LoggerFactory.getLogger(AuditIntegrityTest.class);

    private AccessRequest request(String uid) {
        return new AccessRequest(
                new Subject(uid, Map.of("role", "admin", "dept", "sec")),
                new Resource("res-" + uid, Map.of("sensitivity", "3")),
                "read",
                new EnvironmentContext(Map.of("network", "corp")));
    }

    private DecisionResult result(String version, DecisionOutcome outcome, String rule) {
        return new DecisionResult(outcome, version, rule, "test-reason");
    }

    @Test
    void intactChainVerifies(@TempDir Path dir) {
        AuditLogger logger = new AuditLogger(
                new com.fasterxml.jackson.databind.ObjectMapper(),
                dir.resolve("audit.log").toString());
        logger.init();
        for (int i = 0; i < 5; i++) {
            logger.append(request("u" + i),
                    result("v1", DecisionOutcome.PERMIT, "r1"), UUID.randomUUID().toString());
        }
        AuditVerification v = logger.verify();
        log.info("[完整链校验] intact={}, count={}, detail={}",
                v.intact(), v.recordCount(), v.detail());
        assertTrue(v.intact());
        assertEquals(5, v.recordCount());
    }

    @Test
    void tamperedRecordIsDetected(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit.log");
        AuditLogger logger = new AuditLogger(
                new com.fasterxml.jackson.databind.ObjectMapper(), file.toString());
        logger.init();
        for (int i = 0; i < 4; i++) {
            logger.append(request("u" + i),
                    result("v1", DecisionOutcome.PERMIT, "r1"), UUID.randomUUID().toString());
        }
        // 直接篡改磁盘文件中第 2 行的 outcome，再重载
        List<String> lines = new ArrayList<>(Files.readAllLines(file));
        lines.set(1, lines.get(1).replace("PERMIT", "DENY"));
        Files.write(file, lines);

        AuditLogger reloaded = new AuditLogger(
                new com.fasterxml.jackson.databind.ObjectMapper(), file.toString());
        IllegalStateException ex = assertThrows(IllegalStateException.class, reloaded::init);
        log.info("[篡改检测] 重载被拒绝: {}", ex.getMessage());
        assertTrue(ex.getMessage().contains("篡改"));
    }

    @Test
    void missingRecordIsDetected(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit.log");
        AuditLogger logger = new AuditLogger(
                new com.fasterxml.jackson.databind.ObjectMapper(), file.toString());
        logger.init();
        for (int i = 0; i < 5; i++) {
            logger.append(request("u" + i),
                    result("v1", DecisionOutcome.PERMIT, "r1"), UUID.randomUUID().toString());
        }
        // 删除中间一行制造"缺失"
        List<String> lines = new ArrayList<>(Files.readAllLines(file));
        lines.remove(2);
        Files.write(file, lines);

        AuditLogger reloaded = new AuditLogger(
                new com.fasterxml.jackson.databind.ObjectMapper(), file.toString());
        IllegalStateException ex = assertThrows(IllegalStateException.class, reloaded::init);
        log.info("[缺失检测] 重载被拒绝: {}", ex.getMessage());
        assertTrue(ex.getMessage().contains("不连续") || ex.getMessage().contains("断裂")
                || ex.getMessage().contains("篡改"));
    }

    @Test
    void concurrentAppendsLoseNoRecordAndChainStaysIntact(@TempDir Path dir)
            throws Exception {
        AuditLogger logger = new AuditLogger(
                new com.fasterxml.jackson.databind.ObjectMapper(),
                dir.resolve("audit-concurrent.log").toString());
        logger.init();

        int threads = 16;
        int perThread = 200;
        int total = threads * perThread;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        ConcurrentLinkedQueue<Throwable> errors = new ConcurrentLinkedQueue<>();
        AtomicInteger success = new AtomicInteger();

        for (int t = 0; t < threads; t++) {
            int tid = t;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        logger.append(request("u-" + tid + "-" + i),
                                result("v-concurrent",
                                        (i % 2 == 0) ? DecisionOutcome.PERMIT
                                                : DecisionOutcome.DENY,
                                        "r" + (i % 3)),
                                UUID.randomUUID().toString());
                        success.incrementAndGet();
                    }
                } catch (Throwable e) {
                    errors.add(e);
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(60, TimeUnit.SECONDS), "并发任务未在超时内完成");
        pool.shutdown();

        log.info("[并发审计] 成功写入={}/{}, 错误数={}", success.get(), total, errors.size());
        assertEquals(0, errors.size(), "并发追加出现异常: " + errors);
        assertEquals(total, success.get(), "存在丢失的审计记录");
        assertEquals(total, logger.records().size(), "内存审计记录数不符");

        AuditVerification v = logger.verify();
        log.info("[并发后链校验] intact={}, count={}, detail={}",
                v.intact(), v.recordCount(), v.detail());
        assertTrue(v.intact(), v.detail());

        // 序号必须无重号无空洞
        long expected = 0;
        for (var r : logger.records()) {
            assertEquals(expected, r.seq(), "审计序号出现重号或空洞");
            expected++;
        }
        assertFalse(logger.records().isEmpty());
    }
}
