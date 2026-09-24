package com.github.lisama569.zerotrustauthorizationenginejava.policy;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.github.lisama569.zerotrustauthorizationenginejava.exception.PolicyException;
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
        return new PolicyRule(r.id, r.name, effect,
                r.roles == null ? List.of() : List.copyOf(r.roles),
                r.resourceType, r.maxSensitivity,
                r.actions == null ? List.of() : List.copyOf(r.actions),
                r.requiredEnvironment == null ? Map.of() : Map.copyOf(r.requiredEnvironment));
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
        @JsonProperty("resourceType")
        public String resourceType;
        @JsonProperty("maxSensitivity")
        public Integer maxSensitivity;
        @JsonProperty("actions")
        public List<String> actions;
        @JsonProperty("requiredEnvironment")
        public Map<String, String> requiredEnvironment;
    }
}
