package com.github.lisama569.zerotrustauthorizationenginejava.engine;

import com.github.lisama569.zerotrustauthorizationenginejava.model.AccessRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AttributeSource;
import com.github.lisama569.zerotrustauthorizationenginejava.model.DecisionOutcome;
import com.github.lisama569.zerotrustauthorizationenginejava.model.DecisionResult;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Effect;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Policy;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Rule;
import com.github.lisama569.zerotrustauthorizationenginejava.model.RuleCondition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * 针对固定策略快照的纯函数评估器。
 *
 * <p>求值规则（确定性：不依赖当前时间、随机数或外部状态，
 * 同一策略版本 + 同一输入永远得到同一结论）：
 * <ol>
 *   <li>按声明顺序检查规则；</li>
 *   <li>条件引用的属性键缺失 -> 该规则标记为"上下文缺失"并跳过（不参与匹配）；</li>
 *   <li>条件全部成立 -> 规则命中；</li>
 *   <li>多条命中时拒绝优先：任一 DENY 命中则最终 DENY，否则 PERMIT；</li>
 *   <li>没有规则命中：若存在因缺失被跳过的规则 -> CONTEXT_MISSING，
 *       否则 POLICY_NOT_MATCHED（默认拒绝）；</li>
 *   <li>评估过程任何意外异常 -> EVALUATION_FAILED，异常细节仅入日志不外泄。</li>
 * </ol>
 */
@Component
public class Evaluator {

    private static final Logger log = LoggerFactory.getLogger(Evaluator.class);

    public DecisionResult evaluate(Policy policy, AccessRequest request, String requestId) {
        try {
            return doEvaluate(policy, request, requestId);
        } catch (Exception e) {
            log.error("评估内部异常 requestId={}, version={}, subject={}, resource={}, action={}",
                    requestId, safeVersion(policy), safeSubject(request),
                    safeResource(request), safeAction(request), e);
            return new DecisionResult(
                    DecisionOutcome.EVALUATION_FAILED,
                    safeVersion(policy),
                    null,
                    "评估过程发生内部错误，细节见服务日志");
        }
    }

    private DecisionResult doEvaluate(Policy policy, AccessRequest request, String requestId) {
        String version = policy.version();
        String firstAllow = null;
        String firstDeny = null;
        boolean missing = false;
        String firstMissingReason = null;

        for (Rule rule : policy.rules()) {
            RuleCheck check = checkRule(rule, request);
            if (check.matched) {
                if (rule.effect() == Effect.DENY && firstDeny == null) {
                    firstDeny = rule.id();
                } else if (rule.effect() == Effect.ALLOW && firstAllow == null) {
                    firstAllow = rule.id();
                }
            } else if (check.missingAttribute) {
                missing = true;
                if (firstMissingReason == null) {
                    firstMissingReason = check.detail;
                }
            }
        }

        if (firstDeny != null) {
            String reason = "命中拒绝规则 " + firstDeny
                    + (firstAllow != null ? "（同时命中允许规则 " + firstAllow
                    + "，按拒绝优先裁决）" : "");
            log.info("评估结论 requestId={} version={} subject={} resource={} action={} -> DENY ({})",
                    requestId, version, safeSubject(request), safeResource(request),
                    safeAction(request), reason);
            return new DecisionResult(DecisionOutcome.DENY, version, firstDeny, reason);
        }
        if (firstAllow != null) {
            String reason = "命中允许规则 " + firstAllow;
            log.info("评估结论 requestId={} version={} subject={} resource={} action={} -> PERMIT ({})",
                    requestId, version, safeSubject(request), safeResource(request),
                    safeAction(request), reason);
            return new DecisionResult(DecisionOutcome.PERMIT, version, firstAllow, reason);
        }
        if (missing) {
            String reason = "无规则可完整匹配；上下文缺失: " + firstMissingReason
                    + "（按默认拒绝处理，调用方需补齐上下文后重试）";
            log.info("评估结论 requestId={} version={} subject={} resource={} action={} -> CONTEXT_MISSING ({})",
                    requestId, version, safeSubject(request), safeResource(request),
                    safeAction(request), reason);
            return new DecisionResult(DecisionOutcome.CONTEXT_MISSING, version, null, reason);
        }
        String reason = "没有任何规则匹配该输入，按默认拒绝（deny by default）处理";
        log.info("评估结论 requestId={} version={} subject={} resource={} action={} -> POLICY_NOT_MATCHED",
                requestId, version, safeSubject(request), safeResource(request),
                safeAction(request));
        return new DecisionResult(DecisionOutcome.POLICY_NOT_MATCHED, version, null, reason);
    }

    private RuleCheck checkRule(Rule rule, AccessRequest request) {
        for (RuleCondition condition : rule.conditions()) {
            Map<String, String> attributes = attributesFor(condition.source(), request);
            if (attributes == null || !attributes.containsKey(condition.attribute())) {
                return RuleCheck.missing("规则 " + rule.id() + " 依赖的 "
                        + condition.source() + "." + condition.attribute() + " 缺失");
            }
            String actual = attributes.get(condition.attribute());
            if (!matches(actual, condition)) {
                return RuleCheck.notMatched();
            }
        }
        return RuleCheck.matched();
    }

    private Map<String, String> attributesFor(AttributeSource source, AccessRequest request) {
        return switch (source) {
            case SUBJECT -> request.subject() == null ? null : request.subject().attributes();
            case RESOURCE -> request.resource() == null ? null : request.resource().attributes();
            case ENVIRONMENT -> request.environment() == null
                    ? null : request.environment().attributes();
        };
    }

    private boolean matches(String actual, RuleCondition condition) {
        return switch (condition.op()) {
            case "eq" -> actual.equals(condition.expected());
            case "ne" -> !actual.equals(condition.expected());
            case "in" -> splitList(condition.expected()).contains(actual);
            case "nin" -> !splitList(condition.expected()).contains(actual);
            case "ge" -> compareOrdered(actual, condition.expected()) >= 0;
            case "le" -> compareOrdered(actual, condition.expected()) <= 0;
            default -> false;
        };
    }

    /** in/nin 的期望集合：英文逗号分隔，逐项去除空白；空白项被忽略。 */
    private java.util.List<String> splitList(String expected) {
        java.util.List<String> values = new java.util.ArrayList<>();
        for (String part : expected.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                values.add(trimmed);
            }
        }
        return values;
    }

    /** 优先按数值比较，无法解析为数值时退化为字典序，保证确定性。 */
    private int compareOrdered(String actual, String expected) {
        try {
            return Double.compare(Double.parseDouble(actual), Double.parseDouble(expected));
        } catch (NumberFormatException e) {
            return actual.compareTo(expected);
        }
    }

    private String safeVersion(Policy policy) {
        return policy == null || policy.version() == null ? "unknown" : policy.version();
    }

    private String safeSubject(AccessRequest request) {
        return request == null || request.subject() == null
                ? "?" : request.subject().id();
    }

    private String safeResource(AccessRequest request) {
        return request == null || request.resource() == null
                ? "?" : request.resource().id();
    }

    private String safeAction(AccessRequest request) {
        return request == null || request.action() == null ? "?" : request.action();
    }

    /** 单条规则的检查结果。 */
    private static final class RuleCheck {
        private final boolean matched;
        private final boolean missingAttribute;
        private final String detail;

        private RuleCheck(boolean matched, boolean missingAttribute, String detail) {
            this.matched = matched;
            this.missingAttribute = missingAttribute;
            this.detail = detail;
        }

        static RuleCheck matched() {
            return new RuleCheck(true, false, null);
        }

        static RuleCheck notMatched() {
            return new RuleCheck(false, false, null);
        }

        static RuleCheck missing(String detail) {
            return new RuleCheck(false, true, detail);
        }
    }
}
