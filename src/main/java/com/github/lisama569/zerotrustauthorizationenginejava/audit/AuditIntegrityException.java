package com.github.lisama569.zerotrustauthorizationenginejava.audit;

/**
 * 审计历史无法复核时抛出。
 * 典型场景：旁路基线显示此前已有审计记录，但历史文件整体丢失，
 * 无法判断缺失范围，也不能安全地从零续写。
 * 必须由运维显式处置（归档/清除基线与数据文件后）再重新初始化。
 */
public class AuditIntegrityException extends RuntimeException {

    public AuditIntegrityException(String message) {
        super(message);
    }
}
