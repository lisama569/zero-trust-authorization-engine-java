package com.github.lisama569.zerotrustauthorizationenginejava.web;

import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLogger;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditVerification;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** 审计查询与完整性校验接口。 */
@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final AuditLogger auditLogger;

    public AuditController(AuditLogger auditLogger) {
        this.auditLogger = auditLogger;
    }

    @GetMapping("/records")
    public List<AuditRecord> records() {
        return auditLogger.records();
    }

    @GetMapping("/verify")
    public AuditVerification verify() {
        return auditLogger.verify();
    }

    @PostMapping("/reload")
    public AuditVerification reload() {
        auditLogger.reload();
        return auditLogger.verify();
    }
}
