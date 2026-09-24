package com.github.lisama569.zerotrustauthorizationenginejava.web.dto;

/** 发布策略请求 DTO */
public class PolicyPublishRequest {
    private String policyJson;
    private String note;

    public String getPolicyJson() { return policyJson; }
    public void setPolicyJson(String policyJson) { this.policyJson = policyJson; }
    public String getNote() { return note; }
    public void setNote(String note) { this.note = note; }
}
