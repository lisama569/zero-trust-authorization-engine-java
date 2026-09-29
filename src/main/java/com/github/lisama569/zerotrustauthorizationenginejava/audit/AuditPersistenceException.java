package com.github.lisama569.zerotrustauthorizationenginejava.audit;

/**
 * 审计持久化/恢复异常。
 * 携带出问题的位置（行号或序列号），用于明确指出本地记录被破坏的位置。
 */
public class AuditPersistenceException extends RuntimeException {

    private final String location;

    public AuditPersistenceException(String location, String message) {
        super(message);
        this.location = location;
    }

    public AuditPersistenceException(String location, String message, Throwable cause) {
        super(message, cause);
        this.location = location;
    }

    public String getLocation() {
        return location;
    }
}
