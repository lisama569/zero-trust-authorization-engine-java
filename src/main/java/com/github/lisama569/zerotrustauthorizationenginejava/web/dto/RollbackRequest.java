package com.github.lisama569.zerotrustauthorizationenginejava.web.dto;

/** 回滚请求 DTO */
public class RollbackRequest {
    private String targetVersion;

    public String getTargetVersion() { return targetVersion; }
    public void setTargetVersion(String targetVersion) { this.targetVersion = targetVersion; }
}
