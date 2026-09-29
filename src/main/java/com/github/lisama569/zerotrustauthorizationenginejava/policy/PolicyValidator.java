package com.github.lisama569.zerotrustauthorizationenginejava.policy;

import com.github.lisama569.zerotrustauthorizationenginejava.exception.PolicyException;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AttributeCondition;
import com.github.lisama569.zerotrustauthorizationenginejava.model.ConditionOperator;
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
        if (r.getSubjectConditions() == null) {
            throw new PolicyException(FailureReason.INVALID_CONDITION,
                    "规则 " + r.getId() + " 的 subjectConditions 不能为 null");
        }
        for (AttributeCondition c : r.getSubjectConditions()) {
            validateCondition(r.getId(), c);
        }
    }

    /**
     * 属性条件发布期校验。比较方式是否被引擎支持已在解析阶段以
     * UNSUPPORTED_OPERATOR 挡下；这里负责写法与取值合理性：
     * - attribute 必须非空；
     * - 标量比较（EQ/NE/数值）必须提供非空 value；
     * - 集合比较（IN/NOT_IN）必须提供非空且不含空白元素的 values；
     * - 数值比较的 value 必须可解析为数值。
     */
    private void validateCondition(String ruleId, AttributeCondition c) {
        if (c == null) {
            throw new PolicyException(FailureReason.INVALID_CONDITION,
                    "规则 " + ruleId + " 的属性条件为空");
        }
        if (c.getAttribute() == null || c.getAttribute().isBlank()) {
            throw new PolicyException(FailureReason.INVALID_CONDITION,
                    "规则 " + ruleId + " 的属性条件缺少 attribute");
        }
        ConditionOperator op = c.getOperator();
        if (op == null) {
            throw new PolicyException(FailureReason.UNSUPPORTED_OPERATOR,
                    "规则 " + ruleId + " 的条件 " + c.getAttribute() + " 缺少比较方式");
        }
        if (op.isCollection()) {
            List<String> values = c.getValues();
            if (values == null || values.isEmpty()) {
                throw new PolicyException(FailureReason.INVALID_CONDITION,
                        "规则 " + ruleId + " 的条件 " + c.getAttribute()
                                + " 使用 " + op + " 时必须提供非空 values");
            }
            for (String v : values) {
                if (v == null || v.isBlank()) {
                    throw new PolicyException(FailureReason.INVALID_CONDITION,
                            "规则 " + ruleId + " 的条件 " + c.getAttribute()
                                    + " 的 values 含空元素");
                }
            }
        } else {
            if (c.getValue() == null || c.getValue().isBlank()) {
                throw new PolicyException(FailureReason.INVALID_CONDITION,
                        "规则 " + ruleId + " 的条件 " + c.getAttribute()
                                + " 使用 " + op + " 时必须提供非空 value");
            }
            if (op.isNumeric() && !isNumeric(c.getValue())) {
                throw new PolicyException(FailureReason.INVALID_CONDITION,
                        "规则 " + ruleId + " 的条件 " + c.getAttribute()
                                + " 进行数值比较，但 value 不是数值: " + c.getValue());
            }
        }
    }

    private boolean isNumeric(String s) {
        try {
            new java.math.BigDecimal(s.trim());
            return true;
        } catch (NumberFormatException e) {
            return false;
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
        List<String> conditionSigs = new ArrayList<>();
        for (AttributeCondition c : r.getSubjectConditions()) {
            List<String> vals = c.getOperator().isCollection()
                    ? new ArrayList<>(c.getValues())
                    : new ArrayList<>(List.of(c.getValue() == null ? "" : c.getValue()));
            java.util.Collections.sort(vals);
            conditionSigs.add(c.getAttribute() + " " + c.getOperator() + " " + vals);
        }
        java.util.Collections.sort(conditionSigs);
        return String.join("|",
                String.join(",", roles),
                String.join(";", conditionSigs),
                r.getResourceType(),
                r.getMaxSensitivity().toString(),
                String.join(",", actions),
                new java.util.TreeMap<>(r.getRequiredEnvironment()).toString());
    }
}
