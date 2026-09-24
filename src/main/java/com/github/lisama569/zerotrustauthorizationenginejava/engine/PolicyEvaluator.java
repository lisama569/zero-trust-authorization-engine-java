package com.github.lisama569.zerotrustauthorizationenginejava.engine;

import com.github.lisama569.zerotrustauthorizationenginejava.model.Decision;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Effect;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EnvironmentContext;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationResult;
import com.github.lisama569.zerotrustauthorizationenginejava.model.PolicyRule;
import com.github.lisama569.zerotrustauthorizationenginejava.model.PublishedPolicy;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Resource;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Subject;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 针对单个不可变策略快照执行授权评估（默认拒绝 deny-overrides）。
 *
 * 结论可区分：
 * - DENY：命中至少一条 DENY 规则（显式拒绝优先）；
 * - ALLOW：命中 ALLOW 且未命中任何 DENY；
 * - CONTEXT_MISSING：规则其余条件满足，但 requiredEnvironment 中存在
 *   未提供/为空的环境键（信息缺失不得当作满足或不满足）；
 * - POLICY_NOT_MATCHED：无任何规则命中（默认拒绝）；
 * EVALUATION_FAILED 由服务层在捕获内部异常时产生。
 */
@Component
public class PolicyEvaluator {

    public EvaluationResult evaluate(EvaluationRequest request, Subject subject,
                                     Resource resource, PublishedPolicy snapshot) {
        String version = snapshot.getPolicy().getPolicyVersion();

        List<PolicyRule> matched = new ArrayList<>();
        List<PolicyRule> contextBlocked = new ArrayList<>();

        for (PolicyRule rule : snapshot.getPolicy().getRules()) {
            MatchOutcome outcome = match(rule, subject, resource, request.getAction(),
                    request.getEnvironment());
            if (outcome == MatchOutcome.MATCHED) {
                matched.add(rule);
            } else if (outcome == MatchOutcome.CONTEXT_MISSING) {
                contextBlocked.add(rule);
            }
        }

        PolicyRule deny = matched.stream().filter(r -> r.getEffect() == Effect.DENY)
                .findFirst().orElse(null);
        if (deny != null) {
            return new EvaluationResult(Decision.DENY, version, deny.getId(),
                    "命中显式拒绝规则", null);
        }
        PolicyRule allow = matched.stream().filter(r -> r.getEffect() == Effect.ALLOW)
                .findFirst().orElse(null);
        if (allow != null) {
            return new EvaluationResult(Decision.ALLOW, version, allow.getId(),
                    "命中允许规则且无拒绝规则", null);
        }
        if (!contextBlocked.isEmpty()) {
            return new EvaluationResult(Decision.CONTEXT_MISSING, version,
                    contextBlocked.get(0).getId(),
                    "规则需要的环境上下文缺失: " + missingEnvKeys(contextBlocked.get(0),
                            request.getEnvironment()),
                    null);
        }
        return new EvaluationResult(Decision.POLICY_NOT_MATCHED, version, null,
                "无规则匹配，按默认拒绝处理", null);
    }

    private enum MatchOutcome { MATCHED, NOT_MATCHED, CONTEXT_MISSING }

    private MatchOutcome match(PolicyRule rule, Subject subject, Resource resource,
                               String action, EnvironmentContext env) {
        if (subject == null || resource == null) {
            return MatchOutcome.NOT_MATCHED;
        }
        if (!subject.getRoles().stream().anyMatch(rule.getRoles()::contains)) {
            return MatchOutcome.NOT_MATCHED;
        }
        if (!rule.getResourceType().equals(resource.getResourceType())) {
            return MatchOutcome.NOT_MATCHED;
        }
        if (resource.getSensitivity() > rule.getMaxSensitivity()) {
            return MatchOutcome.NOT_MATCHED;
        }
        if (!rule.getActions().contains(action)) {
            return MatchOutcome.NOT_MATCHED;
        }
        // 其余条件已满足：此时环境键缺失必须显式上报，不能静默
        Map<String, String> envAttrs =
                env == null ? Map.of() : env.getAttributes();
        for (String requiredKey : rule.getRequiredEnvironment().keySet()) {
            String actual = envAttrs.get(requiredKey);
            if (actual == null || actual.isBlank()) {
                return MatchOutcome.CONTEXT_MISSING;
            }
            String expected = rule.getRequiredEnvironment().get(requiredKey);
            if (expected != null && !expected.isBlank() && !expected.equals(actual)) {
                return MatchOutcome.NOT_MATCHED;
            }
        }
        return MatchOutcome.MATCHED;
    }

    private List<String> missingEnvKeys(PolicyRule rule, EnvironmentContext env) {
        Map<String, String> envAttrs = env == null ? Map.of() : env.getAttributes();
        List<String> missing = new ArrayList<>();
        for (String key : rule.getRequiredEnvironment().keySet()) {
            String actual = envAttrs.get(key);
            if (actual == null || actual.isBlank()) {
                missing.add(key);
            }
        }
        return missing;
    }
}
