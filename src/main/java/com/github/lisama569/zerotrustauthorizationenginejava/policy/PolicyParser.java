package com.github.lisama569.zerotrustauthorizationenginejava.policy;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.github.lisama569.zerotrustauthorizationenginejava.exception.PolicyException;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AttributeCondition;
import com.github.lisama569.zerotrustauthorizationenginejava.model.ConditionOperator;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Effect;
import com.github.lisama569.zerotrustauthorizationenginejava.model.FailureReason;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Policy;
import com.github.lisama569.zerotrustauthorizationenginejava.model.PolicyRule;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * 策略 JSON 解析器。
 * 未知字段 -> UNKNOWN_FIELD；JSON 语法/类型错误 -> MALFORMED_POLICY；
 * 结构缺字段 -> MALFORMED_POLICY（取值合法性交给 PolicyValidator）。
 * 绝不静默忽略未知字段。
 */
@Component
public class PolicyParser {

    private final ObjectMapper mapper;

    public PolicyParser() {
        this.mapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
    }

    public Policy parse(String json) {
        if (json == null || json.isBlank()) {
            throw new PolicyException(FailureReason.MALFORMED_POLICY, "策略内容为空");
        }
        PolicyDto dto;
        try {
            dto = mapper.readValue(json, PolicyDto.class);
        } catch (UnrecognizedPropertyException e) {
            throw new PolicyException(FailureReason.UNKNOWN_FIELD,
                    "策略包含未知字段: " + e.getPropertyName());
        } catch (MismatchedInputException e) {
            throw new PolicyException(FailureReason.MALFORMED_POLICY,
                    "策略结构或类型不匹配: " + safeMessage(e));
        } catch (JacksonException e) {
            throw new PolicyException(FailureReason.MALFORMED_POLICY,
                    "策略 JSON 无法解析: " + safeMessage(e));
        }

        List<PolicyRule> rules = dto.rules == null ? List.of()
                : dto.rules.stream().map(PolicyParser::toRule).toList();
        return new Policy(dto.policyVersion, dto.schemaVersion, rules);
    }

    private static PolicyRule toRule(RuleDto r) {
        Effect effect;
        if (r.effect == null) {
            effect = null;
        } else {
            try {
                effect = Effect.valueOf(r.effect);
            } catch (IllegalArgumentException e) {
                throw new PolicyException(FailureReason.MALFORMED_POLICY,
                        "规则 " + r.id + " 的 effect 取值非法: " + r.effect
                                + "（仅允许 ALLOW/DENY）");
            }
        }
        List<AttributeCondition> conditions = r.subjectConditions == null
                ? List.of()
                : r.subjectConditions.stream()
                        .map(c -> toCondition(r.id, c)).toList();
        return new PolicyRule(r.id, r.name, effect,
                r.roles == null ? List.of() : List.copyOf(r.roles),
                conditions,
                r.resourceType, r.maxSensitivity,
                r.actions == null ? List.of() : List.copyOf(r.actions),
                r.requiredEnvironment == null ? Map.of() : Map.copyOf(r.requiredEnvironment));
    }

    private static AttributeCondition toCondition(String ruleId, ConditionDto c) {
        if (c == null) {
            throw new PolicyException(FailureReason.INVALID_CONDITION,
                    "规则 " + ruleId + " 的 subjectConditions 中存在空条件");
        }
        if (c.operator == null || c.operator.isBlank()) {
            throw new PolicyException(FailureReason.INVALID_CONDITION,
                    "规则 " + ruleId + " 的属性条件缺少 operator，attribute="
                            + c.attribute);
        }
        ConditionOperator operator;
        try {
            operator = ConditionOperator.valueOf(c.operator);
        } catch (IllegalArgumentException e) {
            // 比较方式引擎不认识 —— 必须与一般写法非法区分开
            throw new PolicyException(FailureReason.UNSUPPORTED_OPERATOR,
                    "规则 " + ruleId + " 的属性条件使用了不支持的比较方式: "
                            + c.operator + "，attribute=" + c.attribute);
        }
        return new AttributeCondition(c.attribute, operator, c.value,
                c.values == null ? null : List.copyOf(c.values));
    }

    private static String safeMessage(JacksonException e) {
        String m = e.getOriginalMessage();
        return m == null ? "格式错误" : m;
    }

    /** JSON 映射对象：仅允许声明过的字段 */
    public static class PolicyDto {
        @JsonProperty("policyVersion")
        public String policyVersion;
        @JsonProperty("schemaVersion")
        public String schemaVersion;
        @JsonProperty("rules")
        public List<RuleDto> rules;
    }

    public static class RuleDto {
        @JsonProperty("id")
        public String id;
        @JsonProperty("name")
        public String name;
        @JsonProperty("effect")
        public String effect;
        @JsonProperty("roles")
        public List<String> roles;
        @JsonProperty("subjectConditions")
        public List<ConditionDto> subjectConditions;
        @JsonProperty("resourceType")
        public String resourceType;
        @JsonProperty("maxSensitivity")
        public Integer maxSensitivity;
        @JsonProperty("actions")
        public List<String> actions;
        @JsonProperty("requiredEnvironment")
        public Map<String, String> requiredEnvironment;
    }

    /** 主体属性条件 DTO：attribute + operator + value/values */
    public static class ConditionDto {
        @JsonProperty("attribute")
        public String attribute;
        @JsonProperty("operator")
        public String operator;
        @JsonProperty("value")
        public String value;
        @JsonProperty("values")
        public List<String> values;
    }
}
