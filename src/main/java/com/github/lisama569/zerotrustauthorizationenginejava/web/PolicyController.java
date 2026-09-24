package com.github.lisama569.zerotrustauthorizationenginejava.web;

import com.github.lisama569.zerotrustauthorizationenginejava.model.PublishedPolicy;
import com.github.lisama569.zerotrustauthorizationenginejava.service.PolicyGovernanceService;
import com.github.lisama569.zerotrustauthorizationenginejava.web.dto.PolicyPublishRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.web.dto.RollbackRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** 策略治理接口：发布/回滚/当前版本/版本历史 */
@RestController
@RequestMapping("/api/policies")
public class PolicyController {

    private final PolicyGovernanceService governanceService;

    public PolicyController(PolicyGovernanceService governanceService) {
        this.governanceService = governanceService;
    }

    @PostMapping("/publish")
    public ResponseEntity<?> publish(@RequestBody PolicyPublishRequest req) {
        PublishedPolicy snapshot =
                governanceService.publishJson(req.getPolicyJson(), req.getNote());
        return ResponseEntity.ok(toView(snapshot));
    }

    @PostMapping("/rollback")
    public ResponseEntity<?> rollback(@RequestBody RollbackRequest req) {
        PublishedPolicy snapshot = governanceService.rollback(req.getTargetVersion());
        return ResponseEntity.ok(toView(snapshot));
    }

    @GetMapping("/current")
    public ResponseEntity<?> current() {
        PublishedPolicy snapshot = governanceService.current();
        if (snapshot == null) {
            return ResponseEntity.ok(Map.of("policyVersion", null, "message", "尚无生效策略"));
        }
        return ResponseEntity.ok(toView(snapshot));
    }

    @GetMapping("/history")
    public List<String> history() {
        return governanceService.history();
    }

    private Map<String, Object> toView(PublishedPolicy snapshot) {
        return Map.of(
                "policyVersion", snapshot.getPolicy().getPolicyVersion(),
                "schemaVersion", snapshot.getPolicy().getSchemaVersion(),
                "ruleCount", snapshot.getPolicy().getRules().size(),
                "publishedAt", snapshot.getPublishedAt(),
                "note", snapshot.getNote() == null ? "" : snapshot.getNote());
    }
}
