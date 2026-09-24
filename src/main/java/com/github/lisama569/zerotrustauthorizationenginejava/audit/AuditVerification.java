package com.github.lisama569.zerotrustauthorizationenginejava.audit;

/** 审计链校验结果。 */
public record AuditVerification(
        boolean intact,
        long recordCount,
        long firstBrokenSeq,
        String detail
) {
}
