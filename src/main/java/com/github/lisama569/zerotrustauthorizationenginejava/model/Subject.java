package com.github.lisama569.zerotrustauthorizationenginejava.model;

import java.util.List;
import java.util.Map;

/** 主体：身份、角色与属性（本地状态模拟） */
public final class Subject {
    private final String subjectId;
    private final List<String> roles;
    private final Map<String, String> attributes;

    public Subject(String subjectId, List<String> roles, Map<String, String> attributes) {
        this.subjectId = subjectId;
        this.roles = roles;
        this.attributes = attributes;
    }

    public String getSubjectId() { return subjectId; }
    public List<String> getRoles() { return roles; }
    public Map<String, String> getAttributes() { return attributes; }
}
