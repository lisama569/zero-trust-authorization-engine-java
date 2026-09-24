package com.github.lisama569.zerotrustauthorizationenginejava.policy;

import com.github.lisama569.zerotrustauthorizationenginejava.exception.PolicyException;
import com.github.lisama569.zerotrustauthorizationenginejava.model.FailureReason;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Policy;
import com.github.lisama569.zerotrustauthorizationenginejava.model.PolicyRule;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 策略校验器。所有非法情形都抛出带 FailureReason 的 PolicyException，
 * 绝不静默接受：
 * - INVALID_POLICY：版本号缺失、schema 不兼容、规则字段非法；
 * - CONFLICTING_RULES：规则 id 重复，或同一匹配条件同时存在 ALLOW/DENY。
 */
@Component
public class PolicyValidator {

    /** 当前引擎支持的 schema 主版本 */
    public static final String SUPPORTED_SCHEMA = "1.0";

    public void validate(Policy policy) {
        if (policy == null) {
            throw new PolicyException(FailureReason.INVALID_POLICY, "策略为空");
        }
        if (policy.getPolicyVersion() == null || policy.getPolicyVersion().isBlank()) {
            throw new PolicyException(FailureReason.INVALID_POLICY, "policyVersion 缺失");
        }
        if (!isSchemaCompatible(policy.getSchemaVersion())) {
            throw new PolicyException(FailureReason.INVALID_POLICY,
                    "schemaVersion 不兼容，期望 " + SUPPORTED_SCHEMA + "，实际 "
                            + policy.getSchemaVersion());
        }
        List<PolicyRule> rules = policy.getRules();
        if (rules == null || rules.isEmpty()) {
            throw new PolicyException(FailureReason.INVALID_POLICY, "策略至少需要一条规则");
        }

        Set<String> ids = new HashSet<>();
        for (PolicyRule r : rules) {
            validateRule(r, ids);
        }
        detectConflicts(rules);
    }

    private boolean isSchemaCompatible(String schemaVersion) {
        if (schemaVersion == null) {
            return false;
        }
        // 仅支持同主版本（major 相同）
        String supportedMajor = SUPPORTED_SCHEMA.substring(0, SUPPORTED_SCHEMA.indexOf('.'));
        int dot = schemaVersion.indexOf('.');
        String actualMajor = dot < 0 ? schemaVersion : schemaVersion.substring(0, dot);
        return supportedMajor.equals(actualMajor);
    }

    private void validateRule(PolicyRule r, Set<String> ids) {
        if (r == null || r.getId() == null || r.getId().isBlank()) {
            throw new PolicyException(FailureReason.INVALID_POLICY, "规则缺少 id");
        }
        if (!ids.add(r.getId())) {
            throw new PolicyException(FailureReason.CONFLICTING_RULES,
                    "规则 id 重复: " + r.getId());
        }
        if (r.getEffect() == null) {
            throw new PolicyException(FailureReason.INVALID_POLICY,
                    "规则 " + r.getId() + " 缺少合法 effect(ALLOW/DENY)");
        }
        if (r.getActions() == null || r.getActions().isEmpty()) {
            throw new PolicyException(FailureReason.INVALID_POLICY,
                    "规则 " + r.getId() + " 至少需要一个 action");
        }
        if (r.getRoles() == null || r.getRoles().isEmpty()) {
            throw new PolicyException(FailureReason.INVALID_POLICY,
                    "规则 " + r.getId() + " 至少需要一个角色");
        }
        if (r.getResourceType() == null || r.getResourceType().isBlank()) {
            throw new PolicyException(FailureReason.INVALID_POLICY,
                    "规则 " + r.getId() + " 缺少 resourceType");
        }
        Integer max = r.getMaxSensitivity();
        if (max == null || max < 1 || max > 5) {
            throw new PolicyException(FailureReason.INVALID_POLICY,
                    "规则 " + r.getId() + " 的 maxSensitivity 必须在 1..5 之间");
        }
        if (r.getRequiredEnvironment() == null) {
            throw new PolicyException(FailureReason.INVALID_POLICY,
                    "规则 " + r.getId() + " 的 requiredEnvironment 不能为 null");
        }
    }

    /**
     * 冲突检测：若两条规则除 id/name/effect 外的匹配条件完全相同，
     * 却声明了相反 effect，则同一输入会同时命中 ALLOW 与 DENY，
     * 属于必须拒绝发布的冲突规则。
     */
    private void detectConflicts(List<PolicyRule> rules) {
        Map<String, PolicyRule> seen = new HashMap<>();
        for (PolicyRule r : rules) {
            String key = matchSignature(r);
            PolicyRule existing = seen.get(key);
            if (existing != null && existing.getEffect() != r.getEffect()) {
                throw new PolicyException(FailureReason.CONFLICTING_RULES,
                        "规则 " + existing.getId() + " 与 " + r.getId()
                                + " 匹配条件相同但 effect 冲突");
            }
            seen.putIfAbsent(key, r);
        }
    }

    private String matchSignature(PolicyRule r) {
        List<String> roles = new ArrayList<>(r.getRoles());
        List<String> actions = new ArrayList<>(r.getActions());
        java.util.Collections.sort(roles);
        java.util.Collections.sort(actions);
        return String.join("|",
                String.join(",", roles),
                r.getResourceType(),
                r.getMaxSensitivity().toString(),
                String.join(",", actions),
                new java.util.TreeMap<>(r.getRequiredEnvironment()).toString());
    }
}
