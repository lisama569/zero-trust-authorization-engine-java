package com.github.lisama569.zerotrustauthorizationenginejava.web;

import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditHistoryUnavailableException;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLoadOutcome;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLog;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditVerificationResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
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

    /**
     * 历史整体丢失后的显式恢复：隔离残留与旧封签（*.lost-时间戳），重置空历史。
     * 无待恢复状态时返回 409，避免被当作普通重启接口随意调用。
     */
    @PostMapping("/recover-history")
    public ResponseEntity<Map<String, Object>> recoverHistory() {
        try {
            AuditLoadOutcome outcome = auditLog.recoverAfterHistoryLoss();
            return ResponseEntity.ok(Map.of(
                    "recovered", true,
                    "historyLost", false,
                    "detail", outcome.detail()));
        } catch (AuditHistoryUnavailableException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "recovered", false,
                    "historyLost", auditLog.isHistoryLost(),
                    "detail", e.getMessage()));
        }
    }
}
