package com.github.lisama569.zerotrustauthorizationenginejava.web;

import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLog;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditVerificationResult;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** 审计记录查询与哈希链完整性校验 */
@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final AuditLog auditLog;

    public AuditController(AuditLog auditLog) {
        this.auditLog = auditLog;
    }

    @GetMapping("/records")
    public List<AuditRecord> records() {
        return auditLog.all();
    }

    @GetMapping("/verify")
    public ResponseEntity<AuditVerificationResult> verify() {
        return ResponseEntity.ok(auditLog.verify());
    }
}
