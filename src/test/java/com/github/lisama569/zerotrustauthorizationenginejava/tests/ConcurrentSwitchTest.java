package com.github.lisama569.zerotrustauthorizationenginejava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.zerotrustauthorizationenginejava.bootstrap.DefaultPolicySeed;
import com.github.lisama569.zerotrustauthorizationenginejava.engine.AuthorizationService;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AccessRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.DecisionOutcome;
import com.github.lisama569.zerotrustauthorizationenginejava.model.DecisionResult;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EnvironmentContext;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Resource;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Subject;
import com.github.lisama569.zerotrustauthorizationenginejava.versioning.PolicyManagementService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发评估 + 策略切换测试。
 *
 * <p>验证：
 * <ol>
 *   <li>切换期间每个请求的结论与其审计记录中的版本严格自洽，
 *       不允许出现"用 A 版本的部分规则 + B 版本的部分规则"的混合结果；</li>
 *   <li>切换前的请求只看到旧版本，切换完成后的请求只看到新版本；</li>
 *   <li>压力下审计记录数 == 请求数，不丢记录。</li>
 * </ol>
 */
@SpringBootTest(properties = "zt.audit.file=build/audit/concurrent-switch-test.log")
class ConcurrentSwitchTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentSwitchTest.class);

    @Autowired
    private PolicyManagementService managementService;
    @Autowired
    private AuthorizationService authz;
    @Autowired
    private com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLogger auditLogger;
    @Autowired
    private ObjectMapper mapper;

    private AccessRequest request(int i) {
        // 主体/资源/环境在整个测试期间保持不变，消除输入变量
        return new AccessRequest(
                new Subject("u-conc", Map.of("role", "admin")),
                new Resource("d-conc", Map.of()),
                "read",
                new EnvironmentContext(Map.of("network", "corp")));
    }

    private JsonNode singleRulePolicy(String version, String effect) {
        try {
            return mapper.readTree("""
                    {"schemaVersion": 1, "policyId": "root", "version": "%s",
                     "rules": [
                       {"id": "r-admin", "effect": "%s",
                        "conditions": [
                          {"source": "SUBJECT", "attribute": "role", "op": "eq",
                           "expected": "admin"}]}
                     ]}
                    """.formatted(version, effect));
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Test
    void evaluationsDuringSwitchNeverMixVersions() throws Exception {
        managementService.loadAndRegister(singleRulePolicy("cv-allow", "ALLOW"), "test");
        managementService.loadAndRegister(singleRulePolicy("cv-deny", "DENY"), "test");
        managementService.publish("cv-allow");

        int evaluatorThreads = 12;
        int requestsPerThread = 150;
        int totalRequests = evaluatorThreads * requestsPerThread;

        ExecutorService pool = Executors.newFixedThreadPool(evaluatorThreads + 1);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch finished = new CountDownLatch(evaluatorThreads);
        AtomicInteger permits = new AtomicInteger();
        AtomicInteger denies = new AtomicInteger();
        Map<String, AtomicInteger> byVersion = new ConcurrentHashMap<>();

        for (int t = 0; t < evaluatorThreads; t++) {
            int tid = t;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < requestsPerThread; i++) {
                        DecisionResult r = authz.authorize(
                                request(i), "conc-" + tid + "-" + i);
                        // 版本与结论必须自洽：cv-allow => PERMIT；cv-deny => DENY
                        switch (r.version()) {
                            case "cv-allow" -> {
                                assertEquals(DecisionOutcome.PERMIT, r.outcome(),
                                        "cv-allow 版本出现非 PERMIT 结论，疑似混用版本规则");
                                permits.incrementAndGet();
                            }
                            case "cv-deny" -> {
                                assertEquals(DecisionOutcome.DENY, r.outcome(),
                                        "cv-deny 版本出现非 DENY 结论，疑似混用版本规则");
                                denies.incrementAndGet();
                            }
                            default -> throw new AssertionError(
                                    "出现未预期版本: " + r.version());
                        }
                        byVersion.computeIfAbsent(r.version(),
                                k -> new AtomicInteger()).incrementAndGet();
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                } finally {
                    finished.countDown();
                }
            });
        }

        // 在评估压力进行到中段时原子切换到 DENY
        pool.submit(() -> {
            try {
                start.await();
                Thread.sleep(50);
                managementService.publish("cv-deny");
                log.info("[切换器] 已在评估进行中发布 cv-deny");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        start.countDown();
        assertTrue(finished.await(90, TimeUnit.SECONDS), "评估线程未在超时内完成");
        pool.shutdown();

        log.info("[并发切换] 总请求={}, PERMIT={}, DENY={}, 版本分布={}",
                totalRequests, permits.get(), denies.get(), byVersion);
        assertEquals(totalRequests, permits.get() + denies.get());
        assertTrue(permits.get() > 0, "切换前应有请求命中旧版本 cv-allow");
        assertTrue(denies.get() > 0, "切换后应有请求命中新版本 cv-deny");

        // 切换完成之后，所有新请求必须稳定落在新版本
        for (int i = 0; i < 50; i++) {
            DecisionResult r = authz.authorize(request(i), "conc-after-" + i);
            assertEquals("cv-deny", r.version());
            assertEquals(DecisionOutcome.DENY, r.outcome());
        }

        // 审计：本次产生的请求全部可查，数量吻合。
        // 审计文件跨测试运行追加，因此按 requestId 去重计数。
        long audited = auditLogger.records().stream()
                .map(a -> a.requestId())
                .filter(id -> id != null
                        && id.startsWith("conc-")
                        && !id.startsWith("conc-after-"))
                .distinct()
                .count();
        log.info("[并发切换] 审计中 conc-* 请求数={}/{}", audited, totalRequests);
        assertEquals(totalRequests, audited, "并发压力下存在审计记录丢失");

        // 恢复引导版本，避免污染其他测试类共享上下文
        managementService.rollback(DefaultPolicySeed.BOOTSTRAP_VERSION);
    }
}
