package com.github.lisama569.zerotrustauthorizationenginejava.model;

/** 一次访问评估的输入：主体、资源、动作、环境。 */
public record AccessRequest(
        Subject subject,
        Resource resource,
        String action,
        EnvironmentContext environment
) {
}
