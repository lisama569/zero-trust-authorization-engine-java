package com.github.lisama569.zerotrustauthorizationenginejava.validation;

import com.github.lisama569.zerotrustauthorizationenginejava.model.Policy;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Rule;
import com.github.lisama569.zerotrustauthorizationenginejava.model.RuleCondition;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * 策略语义校验。
 *
 * <p>显式拒绝两类问题，不做静默接受：
 * <ul>
 *   <li>{@link PolicyFailureCode#DUPLICATE_RULE_ID}：同一策略内规则 id 重复；</li>
 *   <li>{@link PolicyFailureCode#CONFLICTING_RULES}：两条规则的条件集合完全相同
 *       （与声明顺序无关）但效果相反（ALLOW vs DENY），属于无法消解的冲突。</li>
 * </ul>
 *
 * <p>空规则列表合法：语义上等价于对一切请求默认拒绝（POLICY_NOT_MATCHED）。
 */
@Component
public class PolicyValidator {

    public void validate(Policy policy) {
        if (policy == null) {
            throw new PolicyValidationException(PolicyFailureCode.MALFORMED_JSON,
                    "策略不能为空");
        }

        List<Rule> rules = policy.rules();
        Set<String> seenIds = new HashSet<>();
        List<String> duplicates = new ArrayList<>();
        for (Rule rule : rules) {
            if (!seenIds.add(rule.id())) {
                duplicates.add(rule.id());
            }
        }
        if (!duplicates.isEmpty()) {
            throw new PolicyValidationException(PolicyFailureCode.DUPLICATE_RULE_ID,
                    "策略 " + policy.version() + " 存在重复规则 id: " + duplicates);
        }

        // 条件集合（与顺序无关）-> 各效果对应的规则 id，用于发现同条件反效果冲突。
        Map<Set<String>, Map<String, List<String>>> signatureToEffects = new HashMap<>();
        for (Rule rule : rules) {
            Set<String> signature = new TreeSet<>();
            for (RuleCondition c : rule.conditions()) {
                signature.add(c.source() + "/" + c.attribute() + " " + c.op() + " "
                        + c.expected());
            }
            Map<String, List<String>> byEffect =
                    signatureToEffects.computeIfAbsent(signature, k -> new HashMap<>());
            byEffect.computeIfAbsent(rule.effect().name(), k -> new ArrayList<>())
                    .add(rule.id());
        }

        List<String> conflicts = new ArrayList<>();
        for (Map.Entry<Set<String>, Map<String, List<String>>> entry :
                signatureToEffects.entrySet()) {
            Map<String, List<String>> byEffect = entry.getValue();
            if (byEffect.containsKey("ALLOW") && byEffect.containsKey("DENY")) {
                conflicts.add("规则 " + byEffect.get("ALLOW") + " 与 "
                        + byEffect.get("DENY") + " 条件完全相同但效果冲突（条件: "
                        + entry.getKey() + "）");
            }
        }
        if (!conflicts.isEmpty()) {
            throw new PolicyValidationException(PolicyFailureCode.CONFLICTING_RULES,
                    "策略 " + policy.version() + " 存在冲突规则: " + conflicts);
        }
    }
}
