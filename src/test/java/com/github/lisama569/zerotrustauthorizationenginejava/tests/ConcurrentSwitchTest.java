package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.github.lisama569.zerotrustauthorizationenginejava.model.Decision;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EnvironmentContext;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationResult;
import com.github.lisama569.zerotrustauthorizationenginejava.service.AuthorizationService;
import com.github.lisama569.zerotrustauthorizationenginejava.service.PolicyGovernanceService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 并发评估 + 策略切换测试。
 * 关键不变量：每次评估自始至终使用同一个版本快照的规则——
 * 结论必须与返回的 policyVersion 严格自洽，
 * 不允许出现“v1 版本返回了只有 v2 才有的 ALLOW”这类混用。
 */
@SpringBootTest
class ConcurrentSwitchTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentSwitchTest.class);

    @Autowired
    private AuthorizationService authz;
    @Autowired
    private PolicyGovernanceService governance;

    /** v2 放开 alice 对机密文档的读取，v1 下该输入是 POLICY_NOT_MATCHED */
    private String v2Json(String version) {
        return """
                {
                  "policyVersion": "%s",
                  "schemaVersion": "1.0",
                  "rules": [
                    {"id":"v2-allow-secret","name":"v2放开机密文档","effect":"ALLOW",
                     "roles":["engineer"],"resourceType":"document","maxSensitivity":5,
                     "actions":["read"],"requiredEnvironment":{}}
                  ]
                }
                """.formatted(version);
    }

    @Test
    @DisplayName("评估与发布/回滚并发：结论与版本始终自洽，无混用，审计无丢失")
void concurrentEvaluationAndSwitching() throws InterruptedException {
        // 唯一版本号，避免与同一 Spring 上下文中其它测试发布的版本冲突
        String v2Version = "2.0.0-concurrent-" + UUID.randomUUID();
        // 先发布 v2 再回到 v1：切换期间只用 rollback（目标都已存在），消除“还未发布”的窗口
        governance.publishJson(v2Json(v2Version), "并发测试放开");
        governance.rollback("1.0.0");

        int evaluators = 8;
        long switchNanos = TimeUnit.MILLISECONDS.toNanos(500);
        ExecutorService pool = Executors.newFixedThreadPool(evaluators + 1);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger failures = new AtomicInteger();
        AtomicInteger totalRequests = new AtomicInteger();
        Map<String, AtomicInteger> stats = new ConcurrentHashMap<>();

        for (int t = 0; t < evaluators; t++) {
            pool.submit(() -> {
                try {
                    start.await();
                    // 评估一直跑到切换结束，保证期间两个版本都被使用
                    while (!Thread.currentThread().isInterrupted()) {
                        EvaluationRequest req = new EvaluationRequest(
                                "alice", "read", "doc-secret",
                                new EnvironmentContext(Map.of()));
                        EvaluationResult r = authz.evaluate(req);
                        boolean consistent;
                        if ("1.0.0".equals(r.getPolicyVersion())) {
                            consistent = r.getDecision() == Decision.POLICY_NOT_MATCHED;
                        } else {
                            consistent = v2Version.equals(r.getPolicyVersion())
                                    && r.getDecision() == Decision.ALLOW
                                    && "v2-allow-secret".equals(r.getMatchedRuleId());
                        }
                        if (!consistent) {
                            failures.incrementAndGet();
                            log.error("版本混用! version={} decision={} rule={}",
                                    r.getPolicyVersion(), r.getDecision(), r.getMatchedRuleId());
                        }
                        stats.computeIfAbsent(r.getPolicyVersion() + ":" + r.getDecision(),
                                k -> new AtomicInteger()).incrementAndGet();
                        totalRequests.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }

        CountDownLatch switcherDone = new CountDownLatch(1);
        pool.submit(() -> {
            try {
                start.await();
                long deadline = System.nanoTime() + switchNanos;
                boolean onV2 = false;
                while (System.nanoTime() < deadline) {
                    if (onV2) {
                        governance.rollback("1.0.0");
                    } else {
                        governance.rollback(v2Version);
                    }
                    onV2 = !onV2;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (RuntimeException e) {
                failures.incrementAndGet();
                log.error("切换线程异常", e);
            } finally {
                switcherDone.countDown();
            }
        });

        start.countDown();
        switcherDone.await(30, TimeUnit.SECONDS);
        // 切换结束后停止评估线程
        pool.shutdownNow();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        governance.rollback("1.0.0");

        log.info("并发统计（版本:结论=次数）: {} 总请求={}", stats, totalRequests.get());
        assertEquals(0, failures.get(), "存在版本规则混用的请求或切换异常");
        assertTrue(totalRequests.get() > 0, "应实际产生评估请求");
        assertTrue(stats.containsKey("1.0.0:POLICY_NOT_MATCHED"), "应观察到 v1 结论");
        assertTrue(stats.containsKey(v2Version + ":ALLOW"), "应观察到 v2 结论");
    }
}
