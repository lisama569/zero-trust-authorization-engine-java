package com.github.lisama569.zerotrustauthorizationenginejava.validation;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AttributeSource;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Effect;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Policy;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Rule;
import com.github.lisama569.zerotrustauthorizationenginejava.model.RuleCondition;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * 策略 JSON 解析器：严格模式。
 *
 * <p>失败原因（{@link PolicyFailureCode}）一律显式返回，绝不静默修正：
 * <ul>
 *   <li>MALFORMED_JSON：根节点/字段类型错误；</li>
 *   <li>UNKNOWN_FIELD：出现模型未声明的字段（会收集全部未知字段一次性报错）；</li>
 *   <li>SCHEMA_VERSION_INCOMPATIBLE：schemaVersion 不受支持；</li>
 *   <li>MISSING_REQUIRED_FIELD：必填字段缺失或为空白；</li>
 *   <li>INVALID_ENUM_VALUE：effect / source / op 取值非法。</li>
 * </ul>
 */
@Component
public class PolicyParser {

    /** 当前唯一受支持的策略 schema 版本。 */
    public static final int SUPPORTED_SCHEMA_VERSION = 1;

    private static final Set<String> TOP_LEVEL_FIELDS =
            Set.of("schemaVersion", "policyId", "version", "rules");
    private static final Set<String> RULE_FIELDS = Set.of("id", "effect", "conditions");
    private static final Set<String> CONDITION_FIELDS =
            Set.of("source", "attribute", "op", "expected");
    private static final Set<String> OPS = Set.of("eq", "ne", "in", "nin", "ge", "le");

    public Policy parse(JsonNode root) {
        if (root == null || !root.isObject()) {
            throw new PolicyValidationException(PolicyFailureCode.MALFORMED_JSON,
                    "策略根节点必须是 JSON 对象");
        }

        List<String> unknown = new ArrayList<>();
        root.fieldNames().forEachRemaining(f -> {
            if (!TOP_LEVEL_FIELDS.contains(f)) {
                unknown.add(f);
            }
        });
        if (!unknown.isEmpty()) {
            throw new PolicyValidationException(PolicyFailureCode.UNKNOWN_FIELD,
                    "策略包含未知字段 " + unknown + "，允许的字段为 " + TOP_LEVEL_FIELDS);
        }

        JsonNode schemaNode = root.get("schemaVersion");
        if (schemaNode == null || schemaNode.isNull()) {
            throw new PolicyValidationException(PolicyFailureCode.MISSING_REQUIRED_FIELD,
                    "缺少必填字段 schemaVersion");
        }
        if (!schemaNode.isInt() || schemaNode.asInt() <= 0) {
            throw new PolicyValidationException(PolicyFailureCode.MALFORMED_JSON,
                    "schemaVersion 必须是正整数");
        }
        int schemaVersion = schemaNode.asInt();
        if (schemaVersion != SUPPORTED_SCHEMA_VERSION) {
            throw new PolicyValidationException(PolicyFailureCode.SCHEMA_VERSION_INCOMPATIBLE,
                    "schemaVersion=" + schemaVersion + " 不受支持，当前仅支持 "
                            + SUPPORTED_SCHEMA_VERSION);
        }

        String policyId = requireText(root, "policyId");
        String version = requireText(root, "version");

        JsonNode rulesNode = root.get("rules");
        if (rulesNode == null || rulesNode.isNull()) {
            throw new PolicyValidationException(PolicyFailureCode.MISSING_REQUIRED_FIELD,
                    "缺少必填字段 rules");
        }
        if (!rulesNode.isArray()) {
            throw new PolicyValidationException(PolicyFailureCode.MALFORMED_JSON,
                    "rules 必须是数组");
        }

        List<Rule> rules = new ArrayList<>();
        for (int i = 0; i < rulesNode.size(); i++) {
            rules.add(parseRule(rulesNode.get(i), i));
        }

        return new Policy(schemaVersion, policyId, version, List.copyOf(rules));
    }

    private Rule parseRule(JsonNode node, int index) {
        String where = "rules[" + index + "]";
        if (node == null || !node.isObject()) {
            throw new PolicyValidationException(PolicyFailureCode.MALFORMED_JSON,
                    where + " 必须是对象");
        }
        List<String> unknown = new ArrayList<>();
        node.fieldNames().forEachRemaining(f -> {
            if (!RULE_FIELDS.contains(f)) {
                unknown.add(where + "." + f);
            }
        });
        if (!unknown.isEmpty()) {
            throw new PolicyValidationException(PolicyFailureCode.UNKNOWN_FIELD,
                    "规则包含未知字段 " + unknown + "，允许的字段为 " + RULE_FIELDS);
        }

        String id = requireText(node, where + ".id");

        JsonNode effectNode = node.get("effect");
        if (effectNode == null || effectNode.isNull()) {
            throw new PolicyValidationException(PolicyFailureCode.MISSING_REQUIRED_FIELD,
                    "缺少必填字段 " + where + ".effect");
        }
        Effect effect;
        try {
            effect = Effect.valueOf(effectNode.asText());
        } catch (IllegalArgumentException e) {
            throw new PolicyValidationException(PolicyFailureCode.INVALID_ENUM_VALUE,
                    where + ".effect 非法: " + effectNode.asText()
                            + "，允许值 ALLOW/DENY");
        }

        JsonNode conditionsNode = node.get("conditions");
        if (conditionsNode == null || conditionsNode.isNull()) {
            throw new PolicyValidationException(PolicyFailureCode.MISSING_REQUIRED_FIELD,
                    "缺少必填字段 " + where + ".conditions");
        }
        if (!conditionsNode.isArray()) {
            throw new PolicyValidationException(PolicyFailureCode.MALFORMED_JSON,
                    where + ".conditions 必须是数组");
        }
        List<RuleCondition> conditions = new ArrayList<>();
        for (int j = 0; j < conditionsNode.size(); j++) {
            conditions.add(parseCondition(conditionsNode.get(j),
                    where + ".conditions[" + j + "]"));
        }
        return new Rule(id, effect, List.copyOf(conditions));
    }

    private RuleCondition parseCondition(JsonNode node, String where) {
        if (node == null || !node.isObject()) {
            throw new PolicyValidationException(PolicyFailureCode.MALFORMED_JSON,
                    where + " 必须是对象");
        }
        List<String> unknown = new ArrayList<>();
        node.fieldNames().forEachRemaining(f -> {
            if (!CONDITION_FIELDS.contains(f)) {
                unknown.add(where + "." + f);
            }
        });
        if (!unknown.isEmpty()) {
            throw new PolicyValidationException(PolicyFailureCode.UNKNOWN_FIELD,
                    "条件包含未知字段 " + unknown + "，允许的字段为 " + CONDITION_FIELDS);
        }

        JsonNode sourceNode = node.get("source");
        if (sourceNode == null || sourceNode.isNull()) {
            throw new PolicyValidationException(PolicyFailureCode.MISSING_REQUIRED_FIELD,
                    "缺少必填字段 " + where + ".source");
        }
        AttributeSource source;
        try {
            source = AttributeSource.valueOf(sourceNode.asText());
        } catch (IllegalArgumentException e) {
            throw new PolicyValidationException(PolicyFailureCode.INVALID_ENUM_VALUE,
                    where + ".source 非法: " + sourceNode.asText()
                            + "，允许值 SUBJECT/RESOURCE/ENVIRONMENT");
        }

        String attribute = requireText(node, where + ".attribute");
        String op = requireText(node, where + ".op");
        if (!OPS.contains(op)) {
            throw new PolicyValidationException(PolicyFailureCode.INVALID_ENUM_VALUE,
                    where + ".op 非法: " + op + "，允许值 " + OPS);
        }
        String expected = requireText(node, where + ".expected");
        return new RuleCondition(source, attribute, op, expected);
    }

    /**
     * 从父对象读取非空文本字段。
     *
     * @param parent 直接持有该字段的 JSON 对象
     * @param field  完整字段路径，末段为 JSON 键名，其余仅用于报错信息
     */
    private String requireText(JsonNode parent, String field) {
        String key = field.contains(".") ? field.substring(field.lastIndexOf('.') + 1) : field;
        JsonNode target = parent.get(key);
        if (target == null || target.isNull()) {
            throw new PolicyValidationException(PolicyFailureCode.MISSING_REQUIRED_FIELD,
                    "缺少必填字段 " + field);
        }
        if (!target.isTextual() || target.asText().isBlank()) {
            throw new PolicyValidationException(PolicyFailureCode.MALFORMED_JSON,
                    field + " 必须是非空字符串");
        }
        return target.asText();
    }
}
