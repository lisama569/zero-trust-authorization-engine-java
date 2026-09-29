package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditHasher;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLog;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditVerificationResult;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Decision;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
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
 * 审计哈希链完整性与并发可靠性测试。
 */
class AuditIntegrityTest {

    private static final Logger log = LoggerFactory.getLogger(AuditIntegrityTest.class);

    @Test
    @DisplayName("空链与正常追加链校验通过")
    void intactChain() {
        AuditLog audit = new AuditLog();
        assertTrue(audit.verify().isIntact());
        audit.append("alice", "read", "d1", 3, "ctx", Decision.ALLOW, "r1", "1.0.0");
        audit.append("bob", "read", "d2", 5, "ctx2", Decision.DENY, "r2", "1.0.0");
        AuditVerificationResult v = audit.verify();
        assertTrue(v.isIntact(), v.getDetail());
        assertEquals(2, v.getRecordCount());
        log.info("正常链校验通过 count={}", v.getRecordCount());
    }

    @Test
    @DisplayName("记录内容被篡改 -> 校验失败并定位序列号")
    void tamperedRecordDetected() throws Exception {
        AuditLog audit = new AuditLog();
        audit.append("alice", "read", "d1", 3, "ctx", Decision.ALLOW, "r1", "1.0.0");
        audit.append("bob", "read", "d2", 5, "ctx2", Decision.DENY, "r2", "1.0.0");

        AuditRecord tampered = new AuditRecord(1, "fake-id", 1L, "mallory",
                "write", "d2", 5, "ctx2", null, Decision.ALLOW, "r9", "9.9.9",
                audit.all().get(1).getPreviousHash(),
                audit.all().get(1).getCurrentHash());
        replaceRecord(audit, 1, tampered);

        AuditVerificationResult v = audit.verify();
        assertFalse(v.isIntact());
        assertEquals(1L, v.getBrokenAtSequence());
        log.info("篡改被发现 seq={} detail={}", v.getBrokenAtSequence(), v.getDetail());
    }

    @Test
    @DisplayName("记录被删除 -> 序列号断裂或前驱不匹配，校验失败")
    void missingRecordDetected() throws Exception {
        AuditLog audit = new AuditLog();
        audit.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        audit.append("b", "read", "d", 1, "c", Decision.DENY, "r", "1");
        audit.append("c", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        removeRecord(audit, 1); // 删除中间一条

        AuditVerificationResult v = audit.verify();
        assertFalse(v.isIntact());
        log.info("缺失被发现 seq={} detail={}", v.getBrokenAtSequence(), v.getDetail());
    }

    @Test
    @DisplayName("哈希被重算式伪造但前驱不一致 -> 仍能发现链断裂")
    void recomputedHashStillDetectedViaLink() throws Exception {
        AuditLog audit = new AuditLog();
        audit.append("a", "read", "d", 1, "c", Decision.ALLOW, "r", "1");
        AuditRecord originalSecond = audit.append("b", "read", "d", 1, "c",
                Decision.DENY, "r", "1");
        // 篡改第 0 条并重新计算其自身哈希（无法知道后续记录，链必然断裂）
        AuditRecord fakeFirst = new AuditRecord(0, "x", 0L, "z", "x", "d", 1,
                "c", null, Decision.ALLOW, "r", "1", AuditHasher.GENESIS_HASH, "");
        String newHash = AuditHasher.computeHash(fakeFirst);
        replaceRecord(audit, 0, withHash(fakeFirst, newHash));

        AuditVerificationResult v = audit.verify();
        assertFalse(v.isIntact());
        log.info("重算哈希伪造仍被发现 seq={} detail={}",
                v.getBrokenAtSequence(), v.getDetail());
    }

    @Test
    @DisplayName("并发 16 线程各追加 500 条：不丢记录、序列号唯一连续、链完整")
    void concurrentAppendNoLoss() throws InterruptedException {
        AuditLog audit = new AuditLog();
        int threads = 16;
        int perThread = 500;
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
                                Decision.ALLOW, "rule", "1.0.0");
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
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();

        assertEquals(threads * perThread, audit.size());
        assertEquals(threads * perThread, sequences.size());
        List<Long> sorted = sequences.stream().sorted().collect(Collectors.toList());
        for (int i = 0; i < sorted.size(); i++) {
            assertEquals(i, sorted.get(i), "序列号必须连续不重复");
        }
        AuditVerificationResult v = audit.verify();
        assertTrue(v.isIntact(), "并发写入后哈希链必须完整: " + v.getDetail());
        log.info("并发追加完成 count={} 链完整", audit.size());
    }

    @SuppressWarnings("unchecked")
    private static List<AuditRecord> backingList(AuditLog audit) throws Exception {
        Field f = AuditLog.class.getDeclaredField("records");
        f.setAccessible(true);
        return (List<AuditRecord>) f.get(audit);
    }

    private static void replaceRecord(AuditLog audit, int index, AuditRecord r) throws Exception {
        List<AuditRecord> list = backingList(audit);
        synchronized (audit) {
            list.set(index, r);
        }
    }

    private static void removeRecord(AuditLog audit, int index) throws Exception {
        List<AuditRecord> list = new ArrayList<>(backingList(audit));
        list.remove(index);
        Field f = AuditLog.class.getDeclaredField("records");
        f.setAccessible(true);
        synchronized (audit) {
            List<AuditRecord> target = backingList(audit);
            target.clear();
            target.addAll(list);
        }
    }

    private static AuditRecord withHash(AuditRecord r, String hash) {
        return new AuditRecord(r.getSequence(), r.getAuditId(), r.getTimestamp(),
                r.getSubjectId(), r.getAction(), r.getResourceId(), r.getResourceSensitivity(),
                r.getContextSummary(), r.getConditionEvidence(), r.getDecision(),
                r.getMatchedRuleId(), r.getPolicyVersion(), r.getPreviousHash(), hash);
    }
}
