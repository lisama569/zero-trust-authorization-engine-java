package com.github.lisama569.zerotrustauthorizationenginejava.versioning;

import com.github.lisama569.zerotrustauthorizationenginejava.model.Policy;

import java.time.Instant;

/** 一个不可变的已注册策略版本快照。 */
public record PolicyVersion(
        Policy policy,
        Instant createdAt,
        String source
) {
}
