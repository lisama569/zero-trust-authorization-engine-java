package com.github.lisama569.zerotrustauthorizationenginejava.model;

/** 一次授权评估请求：主体 + 动作 + 资源 + 环境 */
public final class EvaluationRequest {
    private final String subjectId;
    private final String action;
    private final String resourceId;
    private final EnvironmentContext environment;

    public EvaluationRequest(String subjectId, String action, String resourceId,
                             EnvironmentContext environment) {
        this.subjectId = subjectId;
        this.action = action;
        this.resourceId = resourceId;
        this.environment = environment;
    }

    public String getSubjectId() { return subjectId; }
    public String getAction() { return action; }
    public String getResourceId() { return resourceId; }
    public EnvironmentContext getEnvironment() { return environment; }
}
