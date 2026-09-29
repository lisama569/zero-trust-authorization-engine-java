package com.github.lisama569.zerotrustauthorizationenginejava.engine;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AttributeCondition;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Decision;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Effect;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EnvironmentContext;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationResult;
import com.github.lisama569.zerotrustauthorizationenginejava.model.MatchEvidence;
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
 * - CONTEXT_MISSING：规则其余条件满足，但 requiredEnvironment 存在未提供/为空的
 *   环境键，或 subjectConditions 引用的主体属性未提供（信息缺失不得当作满足或不满足）；
 * - POLICY_NOT_MATCHED：无任何规则命中（默认拒绝，含“属性在但不满足”）；
 * EVALUATION_FAILED 由服务层在捕获内部异常时产生。
 */
@Component
public class PolicyEvaluator {

    public EvaluationResult evaluate(EvaluationRequest request, Subject subject,
                                     Resource resource, PublishedPolicy snapshot) {
        String version = snapshot.getPolicy().getPolicyVersion();

        List<PolicyRule> matched = new ArrayList<>();
        List<RuleBlock> contextBlocked = new ArrayList<>();

        for (PolicyRule rule : snapshot.getPolicy().getRules()) {
            RuleAssessment assessment = assess(rule, subject, resource, request.getAction(),
                    request.getEnvironment());
            if (assessment.outcome == MatchOutcome.MATCHED) {
                matched.add(rule);
            } else if (assessment.outcome == MatchOutcome.CONTEXT_MISSING) {
                contextBlocked.add(new RuleBlock(rule, assessment.evidence));
            }
        }

        PolicyRule deny = matched.stream().filter(r -> r.getEffect() == Effect.DENY)
                .findFirst().orElse(null);
        if (deny != null) {
            return new EvaluationResult(Decision.DENY, version, deny.getId(),
                    "命中显式拒绝规则", null, evidenceOf(deny));
        }
        PolicyRule allow = matched.stream().filter(r -> r.getEffect() == Effect.ALLOW)
                .findFirst().orElse(null);
        if (allow != null) {
            return new EvaluationResult(Decision.ALLOW, version, allow.getId(),
                    "命中允许规则且无拒绝规则", null, evidenceOf(allow));
        }
        if (!contextBlocked.isEmpty()) {
            RuleBlock block = contextBlocked.get(0);
            return new EvaluationResult(Decision.CONTEXT_MISSING, version,
                    block.rule.getId(),
                    "规则需要的上下文缺失: " + describeMissing(block.rule,
                            request.getEnvironment(), block.evidence),
                    null, block.evidence);
        }
        return new EvaluationResult(Decision.POLICY_NOT_MATCHED, version, null,
                "无规则匹配，按默认拒绝处理", null);
    }

    /** 命中规则的证据：其全部主体属性条件都已实际核对 */
    private MatchEvidence evidenceOf(PolicyRule rule) {
        List<String> evaluated = new ArrayList<>();
        for (AttributeCondition c : rule.getSubjectConditions()) {
            evaluated.add(c.getAttribute() + "[" + c.getOperator() + "]");
        }
        return new MatchEvidence(evaluated, List.of());
    }

    private String describeMissing(PolicyRule rule, EnvironmentContext env, MatchEvidence evidence) {
        List<String> missing = new ArrayList<>(evidence.getMissingAttributes());
        Map<String, String> envAttrs = env == null ? Map.of() : env.getAttributes();
        for (String requiredKey : rule.getRequiredEnvironment().keySet()) {
            String actual = envAttrs.get(requiredKey);
            if (actual == null || actual.isBlank()) {
                missing.add(requiredKey);
            }
        }
        return missing.toString();
    }

    private enum MatchOutcome { MATCHED, NOT_MATCHED, CONTEXT_MISSING }

    /** 单条规则的评估中间态及其证据 */
    private static final class RuleAssessment {
        final MatchOutcome outcome;
        final MatchEvidence evidence;

        RuleAssessment(MatchOutcome outcome, MatchEvidence evidence) {
            this.outcome = outcome;
            this.evidence = evidence;
        }
    }

    private record RuleBlock(PolicyRule rule, MatchEvidence evidence) {
    }

    private RuleAssessment assess(PolicyRule rule, Subject subject, Resource resource,
                                  String action, EnvironmentContext env) {
        if (subject == null || resource == null) {
            return new RuleAssessment(MatchOutcome.NOT_MATCHED, null);
        }
        if (!subject.getRoles().stream().anyMatch(rule.getRoles()::contains)) {
            return new RuleAssessment(MatchOutcome.NOT_MATCHED, null);
        }
        if (!rule.getResourceType().equals(resource.getResourceType())) {
            return new RuleAssessment(MatchOutcome.NOT_MATCHED, null);
        }
        if (resource.getSensitivity() > rule.getMaxSensitivity()) {
            return new RuleAssessment(MatchOutcome.NOT_MATCHED, null);
        }
        if (!rule.getActions().contains(action)) {
            return new RuleAssessment(MatchOutcome.NOT_MATCHED, null);
        }

        // 主体属性附加条件：全部满足才算命中；属性缺失与不满足严格区分
        List<String> evaluated = new ArrayList<>();
        List<String> missing = new ArrayList<>();
        for (AttributeCondition condition : rule.getSubjectConditions()) {
            evaluated.add(condition.getAttribute() + "[" + condition.getOperator() + "]");
            AttributeConditionMatcher.Result r =
                    AttributeConditionMatcher.matches(condition, subject.getAttributes());
            if (r == AttributeConditionMatcher.Result.MISSING) {
                missing.add(condition.getAttribute());
            } else if (r == AttributeConditionMatcher.Result.NOT_MATCHED) {
                // 属性在但不满足：该规则直接不匹配，不能因为缺别的属性又回到 CONTEXT_MISSING
                return new RuleAssessment(MatchOutcome.NOT_MATCHED, null);
            }
        }
        MatchEvidence attrEvidence = new MatchEvidence(evaluated, missing);
        if (!missing.isEmpty()) {
            return new RuleAssessment(MatchOutcome.CONTEXT_MISSING, attrEvidence);
        }

        // 其余条件已满足：此时环境键缺失必须显式上报，不能静默
        Map<String, String> envAttrs =
                env == null ? Map.of() : env.getAttributes();
        for (String requiredKey : rule.getRequiredEnvironment().keySet()) {
            String actual = envAttrs.get(requiredKey);
            if (actual == null || actual.isBlank()) {
                return new RuleAssessment(MatchOutcome.CONTEXT_MISSING, attrEvidence);
            }
            String expected = rule.getRequiredEnvironment().get(requiredKey);
            if (expected != null && !expected.isBlank() && !expected.equals(actual)) {
                return new RuleAssessment(MatchOutcome.NOT_MATCHED, null);
            }
        }
        return new RuleAssessment(MatchOutcome.MATCHED, attrEvidence);
    }
}
