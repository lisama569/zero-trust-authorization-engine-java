package com.github.lisama569.zerotrustauthorizationenginejava.engine;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AttributeCondition;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AttributeOperator;
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

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 针对单个不可变策略快照执行授权评估（默认拒绝 deny-overrides）。
 *
 * 规则在角色/资源类型/敏感级/动作均满足后，还要同时满足：
 * - 主体属性条件 attributeConditions；
 * - 环境条件 requiredEnvironment。
 *
 * “缺失”与“不满足”严格区分，二者都绝不默认放行：
 * - 属性/环境键未提供或为空白 => CONTEXT_MISSING（可补全后重试）；
 * - 键存在但值不满足条件 => 该规则 NOT_MATCHED（默认拒绝）。
 * 同一条规则上若同时出现“不满足”和“缺失”，按 NOT_MATCHED 处理
 * （已有信息已足以否定规则，见同名测试）。
 *
 * 结论：DENY（命中显式拒绝）、ALLOW（命中 ALLOW 且无 DENY）、
 * CONTEXT_MISSING（存在只差上下文的规则）、POLICY_NOT_MATCHED（默认拒绝）。
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
                    "命中显式拒绝规则", null, conditionBasis(deny, subject));
        }
        PolicyRule allow = matched.stream().filter(r -> r.getEffect() == Effect.ALLOW)
                .findFirst().orElse(null);
        if (allow != null) {
            return new EvaluationResult(Decision.ALLOW, version, allow.getId(),
                    "命中允许规则且无拒绝规则", null, conditionBasis(allow, subject));
        }
        if (!contextBlocked.isEmpty()) {
            PolicyRule blocked = contextBlocked.get(0);
            return new EvaluationResult(Decision.CONTEXT_MISSING, version,
                    blocked.getId(),
                    "规则需要的上下文缺失: " + describeMissing(blocked, subject,
                            request.getEnvironment()),
                    null, conditionBasis(blocked, subject));
        }
        return new EvaluationResult(Decision.POLICY_NOT_MATCHED, version, null,
                "无规则匹配，按默认拒绝处理", null, "");
    }

    private enum MatchOutcome { MATCHED, NOT_MATCHED, CONTEXT_MISSING }

    private MatchOutcome match(PolicyRule rule, Subject subject, Resource resource,
                               String action, EnvironmentContext env) {
        if (subject == null || resource == null) {
            return MatchOutcome.NOT_MATCHED;
        }
        if (subject.getRoles().stream().noneMatch(rule.getRoles()::contains)) {
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
        // 硬维度均满足：此后严格评估属性条件与环境条件，缺失不得当作放行
        MatchOutcome attrs = matchAttributeConditions(rule, subject);
        if (attrs == MatchOutcome.NOT_MATCHED) {
            return MatchOutcome.NOT_MATCHED;
        }
        MatchOutcome envOutcome = matchEnvironment(rule, env);
        if (envOutcome == MatchOutcome.NOT_MATCHED) {
            return MatchOutcome.NOT_MATCHED;
        }
        // 没有任何“值不满足”，属性或环境任一缺失即 CONTEXT_MISSING
        if (attrs == MatchOutcome.CONTEXT_MISSING || envOutcome == MatchOutcome.CONTEXT_MISSING) {
            return MatchOutcome.CONTEXT_MISSING;
        }
        return MatchOutcome.MATCHED;
    }

    /**
     * 评估全部属性条件：任一条件“有值但不满足” => NOT_MATCHED；
     * 否则只要存在“属性缺失/空白” => CONTEXT_MISSING；全部满足 => MATCHED。
     */
    private MatchOutcome matchAttributeConditions(PolicyRule rule, Subject subject) {
        Map<String, String> attrs = subject.getAttributes() == null
                ? Map.of() : subject.getAttributes();
        boolean anyMissing = false;
        for (AttributeCondition c : rule.getAttributeConditions()) {
            String actual = attrs.get(c.getAttribute());
            if (actual == null || actual.isBlank()) {
                anyMissing = true;
                continue;
            }
            if (!satisfies(c, actual)) {
                return MatchOutcome.NOT_MATCHED;
            }
        }
        return anyMissing ? MatchOutcome.CONTEXT_MISSING : MatchOutcome.MATCHED;
    }

    private MatchOutcome matchEnvironment(PolicyRule rule, EnvironmentContext env) {
        Map<String, String> envAttrs = env == null ? Map.of() : env.getAttributes();
        boolean anyMissing = false;
        for (String requiredKey : rule.getRequiredEnvironment().keySet()) {
            String actual = envAttrs.get(requiredKey);
            if (actual == null || actual.isBlank()) {
                anyMissing = true;
                continue;
            }
            String expected = rule.getRequiredEnvironment().get(requiredKey);
            if (expected != null && !expected.isBlank() && !expected.equals(actual)) {
                return MatchOutcome.NOT_MATCHED;
            }
        }
        return anyMissing ? MatchOutcome.CONTEXT_MISSING : MatchOutcome.MATCHED;
    }

    /** 单个条件判定。数值比较在两侧均可解析为数值时进行，否则视为不满足。 */
    private boolean satisfies(AttributeCondition c, String actual) {
        AttributeOperator op = c.getOperator();
        String expected = c.getValues().get(0);
        return switch (op) {
            case EQ -> actual.equals(expected);
            case NE -> !actual.equals(expected);
            case IN -> c.getValues().contains(actual);
            case NOT_IN -> !c.getValues().contains(actual);
            case GT, GTE, LT, LTE -> compareNumeric(op, actual, expected);
        };
    }

    private boolean compareNumeric(AttributeOperator op, String actual, String expected) {
        BigDecimal a = parseNumber(actual);
        BigDecimal b = parseNumber(expected);
        if (a == null || b == null) {
            // 有值但无法按数值解释：属于“值不满足”，不是缺失
            return false;
        }
        int cmp = a.compareTo(b);
        return switch (op) {
            case GT -> cmp > 0;
            case GTE -> cmp >= 0;
            case LT -> cmp < 0;
            case LTE -> cmp <= 0;
            default -> false;
        };
    }

    private static BigDecimal parseNumber(String s) {
        try {
            return new BigDecimal(s.trim());
        } catch (NumberFormatException e) {
            return null;
        }
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

    /** 汇总缺失的主体属性键与环境键（仅键名，便于调用方补全上下文） */
    private String describeMissing(PolicyRule rule, Subject subject, EnvironmentContext env) {
        Map<String, String> attrs = subject.getAttributes() == null
                ? Map.of() : subject.getAttributes();
        List<String> missingAttrs = new ArrayList<>();
        for (AttributeCondition c : rule.getAttributeConditions()) {
            String actual = attrs.get(c.getAttribute());
            if (actual == null || actual.isBlank()) {
                missingAttrs.add(c.getAttribute());
            }
        }
        List<String> parts = new ArrayList<>();
        if (!missingAttrs.isEmpty()) {
            parts.add("主体属性缺失 " + missingAttrs);
        }
        List<String> envKeys = missingEnvKeys(rule, env);
        if (!envKeys.isEmpty()) {
            parts.add("环境键缺失 " + envKeys);
        }
        return String.join("; ", parts);
    }

    /**
     * 审计/复盘用条件依据：列出规则声明的每个属性条件、期望值、
     * 主体实际值以及该条件是否满足。仅包含规则引用到的属性。
     */
    private String conditionBasis(PolicyRule rule, Subject subject) {
        if (rule.getAttributeConditions().isEmpty()) {
            return "";
        }
        Map<String, String> attrs = subject == null || subject.getAttributes() == null
                ? Map.of() : subject.getAttributes();
        List<String> parts = new ArrayList<>();
        for (AttributeCondition c : rule.getAttributeConditions()) {
            String actual = attrs.get(c.getAttribute());
            String actualView = actual == null ? "<missing>" : actual;
            String expected = c.getOperator().isSetBased()
                    ? c.getValues().toString()
                    : c.getValues().get(0);
            boolean ok = actual != null && !actual.isBlank() && satisfies(c, actual);
            parts.add(c.getAttribute() + " " + c.getOperator() + " " + expected
                    + " (actual=" + actualView + ", " + (ok ? "满足" : "未满足") + ")");
        }
        return String.join("; ", parts);
    }
}
