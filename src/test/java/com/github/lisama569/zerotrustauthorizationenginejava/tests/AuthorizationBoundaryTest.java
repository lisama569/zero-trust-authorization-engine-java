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

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 权限边界测试：资源敏感级别 + 主体属性 + 环境条件组合。
 *
 * <p>策略 bnd-v1：
 * <ul>
 *   <li>sensitivity ge 4 一律 DENY（高敏资源边界，即使管理员也拒绝）；</li>
 *   <li>否则 role=admin 且 network=corp 才 ALLOW；</li>
 * </ul>
 */
@SpringBootTest(properties = "zt.audit.file=build/audit/boundary-test.log")
class AuthorizationBoundaryTest {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationBoundaryTest.class);

    @Autowired
    private PolicyManagementService managementService;
    @Autowired
    private AuthorizationService authz;
    @Autowired
    private ObjectMapper mapper;

    private AccessRequest request(String role, String sensitivity, String network) {
        return new AccessRequest(
                new Subject("u-bnd", Map.of("role", role)),
                new Resource("r-bnd", Map.of("sensitivity", sensitivity)),
                "read",
                network == null
                        ? new EnvironmentContext(Map.of())
                        : new EnvironmentContext(Map.of("network", network)));
    }

    private DecisionResult eval(AccessRequest r, String name) {
        DecisionResult result = authz.authorize(r, "bnd-" + name);
        log.info("[边界用例 {}] role={}, sensitivity={}, network={} => {} @ {}, 依据={}",
                name,
                r.subject().attributes().get("role"),
                r.resource().attributes().get("sensitivity"),
                r.environment().attributes().get("network"),
                result.outcome(), result.version(), result.reason());
        return result;
    }

    @Test
    void boundaryCasesAreDistinguishable() throws Exception {
        String json = """
                {
                  "schemaVersion": 1, "policyId": "boundary", "version": "bnd-v1",
                  "rules": [
                    {"id": "deny-high-sensitivity", "effect": "DENY", "conditions": [
                      {"source": "RESOURCE", "attribute": "sensitivity", "op": "ge",
                       "expected": "4"}]},
                    {"id": "allow-admin-corp", "effect": "ALLOW", "conditions": [
                      {"source": "SUBJECT", "attribute": "role", "op": "eq",
                       "expected": "admin"},
                      {"source": "ENVIRONMENT", "attribute": "network", "op": "eq",
                       "expected": "corp"}]}
                  ]
                }
                """;
        JsonNode node = mapper.readTree(json);
        try {
            managementService.loadAndRegister(node, "boundary-test");
        } catch (Exception e) {
            // 允许重复运行时版本已存在
        }
        managementService.publish("bnd-v1");

        try {
            // 1. 普通管理员 + 低敏 + 内网 => 允许
            assertEquals(DecisionOutcome.PERMIT,
                    eval(request("admin", "1", "corp"), "admin-low-corp").outcome());

            // 2. 管理员 + 高敏(4) + 内网 => 显式拒绝（敏感级别边界压过身份）
            assertEquals(DecisionOutcome.DENY,
                    eval(request("admin", "4", "corp"), "admin-high-corp").outcome());

            // 3. 管理员 + 高敏(5) => 拒绝（ge 比较生效）
            assertEquals(DecisionOutcome.DENY,
                    eval(request("admin", "5", "corp"), "admin-higher").outcome());

            // 4. 访客 + 低敏 + 内网 => 无规则匹配 -> 默认拒绝
            assertEquals(DecisionOutcome.POLICY_NOT_MATCHED,
                    eval(request("guest", "1", "corp"), "guest-low").outcome());

            // 5. 管理员 + 低敏 + 外网(vpn) => 无匹配 -> 默认拒绝
            assertEquals(DecisionOutcome.POLICY_NOT_MATCHED,
                    eval(request("admin", "1", "vpn"), "admin-low-vpn").outcome());

            // 6. 管理员 + 低敏 + 缺网络环境 => 上下文缺失
            assertEquals(DecisionOutcome.CONTEXT_MISSING,
                    eval(request("admin", "1", null), "admin-no-env").outcome());
        } finally {
            managementService.rollback(DefaultPolicySeed.BOOTSTRAP_VERSION);
        }
    }
}
