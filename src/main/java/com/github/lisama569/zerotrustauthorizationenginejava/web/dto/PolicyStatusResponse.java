package com.github.lisama569.zerotrustauthorizationenginejava.web.dto;

import java.util.List;

/** 策略版本库状态。 */
public record PolicyStatusResponse(
        String currentVersion,
        List<String> registeredVersions
) {
}
