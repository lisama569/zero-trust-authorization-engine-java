package com.github.lisama569.zerotrustauthorizationenginejava.web.dto;

import java.util.Map;

/** 评估请求 DTO */
public class EvaluationRequestDto {
    private String subjectId;
    private String action;
    private String resourceId;
    private Map<String, String> environment;

    public String getSubjectId() { return subjectId; }
    public void setSubjectId(String subjectId) { this.subjectId = subjectId; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public String getResourceId() { return resourceId; }
    public void setResourceId(String resourceId) { this.resourceId = resourceId; }
    public Map<String, String> getEnvironment() { return environment; }
    public void setEnvironment(Map<String, String> environment) { this.environment = environment; }
}
