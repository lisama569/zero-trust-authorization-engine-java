package com.github.lisama569.zerotrustauthorizationenginejava.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Policy;
import com.github.lisama569.zerotrustauthorizationenginejava.versioning.PolicyManagementService;
import com.github.lisama569.zerotrustauthorizationenginejava.versioning.PolicyStore;
import com.github.lisama569.zerotrustauthorizationenginejava.web.dto.PolicyStatusResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 策略治理 REST 接口：加载注册、发布、回滚、状态查询。 */
@RestController
@RequestMapping("/api/policies")
public class PolicyController {

    private final PolicyManagementService managementService;
    private final PolicyStore policyStore;

    public PolicyController(PolicyManagementService managementService,
                            PolicyStore policyStore) {
        this.managementService = managementService;
        this.policyStore = policyStore;
    }

    /** 加载并注册一份策略（严格校验，不自动发布）。 */
    @PostMapping("/load")
    public Policy load(@RequestBody JsonNode body) {
        return managementService.loadAndRegister(body, "api");
    }

    /** 发布已注册版本。 */
    @PostMapping("/{version}/publish")
    public PolicyStatusResponse publish(@PathVariable String version) {
        managementService.publish(version);
        return status();
    }

    /** 回滚到已注册历史版本；目标不存在返回 ROLLBACK_TARGET_NOT_FOUND。 */
    @PostMapping("/{version}/rollback")
    public PolicyStatusResponse rollback(@PathVariable String version) {
        managementService.rollback(version);
        return status();
    }

    @GetMapping("/status")
    public PolicyStatusResponse status() {
        String current = policyStore.current()
                .map(pv -> pv.policy().version())
                .orElse(null);
        return new PolicyStatusResponse(current, policyStore.versions());
    }
}
