package com.github.lisama569.zerotrustauthorizationenginejava.model;

import java.util.List;
import java.util.Map;

/**
 * 单条策略规则（不可变）。
 * 匹配维度：角色、主体属性、资源类型、资源敏感级别上限、动作、环境条件。
 */
public final class PolicyRule {
    private final String id;
    private final String name;
    private final Effect effect;
    private final List<String> roles;
    private final String resourceType;
    private final Integer maxSensitivity;
    private final List<String> actions;
    private final Map<String, String> requiredEnvironment;

    public PolicyRule(String id, String name, Effect effect, List<String> roles,
                      String resourceType, Integer maxSensitivity, List<String> actions,
                      Map<String, String> requiredEnvironment) {
        this.id = id;
        this.name = name;
        this.effect = effect;
        this.roles = roles;
        this.resourceType = resourceType;
        this.maxSensitivity = maxSensitivity;
        this.actions = actions;
        this.requiredEnvironment = requiredEnvironment;
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public Effect getEffect() { return effect; }
    public List<String> getRoles() { return roles; }
    public String getResourceType() { return resourceType; }
    public Integer getMaxSensitivity() { return maxSensitivity; }
    public List<String> getActions() { return actions; }
    public Map<String, String> getRequiredEnvironment() { return requiredEnvironment; }
}
