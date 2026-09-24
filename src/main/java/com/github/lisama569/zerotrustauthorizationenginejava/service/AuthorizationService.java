package com.github.lisama569.zerotrustauthorizationenginejava.service;

import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLog;
import com.github.lisama569.zerotrustauthorizationenginejava.directory.LocalDirectory;
import com.github.lisama569.zerotrustauthorizationenginejava.engine.PolicyEvaluator;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AuditRecord;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Decision;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EnvironmentContext;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.EvaluationResult;
import com.github.lisama569.zerotrustauthorizationenginejava.model.PublishedPolicy;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Resource;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Subject;
import com.github.lisama569.zerotrustauthorizationenginejava.version.PolicyVersionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.TreeMap;

/**
 * 授权服务门面。
 *
 * 版本一致性：请求开始时读取一次当前快照引用并贯穿评估与审计，
 * 即便期间发生发布/回滚，本请求也不会混用新旧规则。
 * 默认拒绝：主体/资源未知、无生效策略等一切非明确允许情形均拒绝。
 * 异常收口：内部异常只映射为 EVALUATION_FAILED，不外泄堆栈。
 * 审计必留痕：每条评估（含失败）都追加哈希链记录。
 */
@Service
public class AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationService.class);

    private final PolicyVersionManager versionManager;
    private final PolicyEvaluator evaluator;
    private final LocalDirectory directory;
    private final AuditLog auditLog;

    public AuthorizationService(PolicyVersionManager versionManager, PolicyEvaluator evaluator,
                                LocalDirectory directory, AuditLog auditLog) {
        this.versionManager = versionManager;
        this.evaluator = evaluator;
        this.directory = directory;
        this.auditLog = auditLog;
    }

    public EvaluationResult evaluate(EvaluationRequest request) {
        PublishedPolicy snapshot = versionManager.current();
        Subject subject = null;
        Resource resource = null;
        Decision decision;
        String matchedRuleId = null;
        String reason;
        String version = snapshot == null ? null : snapshot.getPolicy().getPolicyVersion();

        try {
            validateRequest(request);
            subject = directory.findSubject(request.getSubjectId()).orElse(null);
            resource = directory.findResource(request.getResourceId()).orElse(null);

            if (snapshot == null) {
                decision = Decision.EVALUATION_FAILED;
                reason = "当前无已生效策略版本";
            } else if (subject == null) {
                decision = Decision.POLICY_NOT_MATCHED;
                reason = "未知主体，默认拒绝";
            } else if (resource == null) {
                decision = Decision.POLICY_NOT_MATCHED;
                reason = "未知资源，默认拒绝";
            } else {
                EvaluationResult r = evaluator.evaluate(request, subject, resource, snapshot);
                decision = r.getDecision();
                matchedRuleId = r.getMatchedRuleId();
                reason = r.getReason();
            }
        } catch (IllegalArgumentException e) {
            decision = Decision.POLICY_NOT_MATCHED;
            reason = "请求参数非法，默认拒绝: " + e.getMessage();
            log.warn("非法评估输入 subjectId={} action={} resourceId={} : {}",
                    request == null ? null : request.getSubjectId(),
                    request == null ? null : request.getAction(),
                    request == null ? null : request.getResourceId(), e.getMessage());
        } catch (RuntimeException e) {
            // 内部异常绝不穿透到对外结果
            decision = Decision.EVALUATION_FAILED;
            reason = "评估过程中发生内部错误，已拒绝";
            log.error("评估内部异常 subjectId={} action={} resourceId={}",
                    request == null ? null : request.getSubjectId(),
                    request == null ? null : request.getAction(),
                    request == null ? null : request.getResourceId(), e);
        }

        String contextSummary = summarize(request, subject, resource);
        AuditRecord record = auditLog.append(
                request == null ? null : request.getSubjectId(),
                request == null ? null : request.getAction(),
                request == null ? null : request.getResourceId(),
                resource == null ? null : resource.getSensitivity(),
                contextSummary, decision, matchedRuleId, version);

        log.info("授权评估 input[subject={}, action={}, resource={}, env={}] version={} decision={} matchedRule={} basis='{}' auditSeq={}",
                request == null ? null : request.getSubjectId(),
                request == null ? null : request.getAction(),
                request == null ? null : request.getResourceId(),
                request == null || request.getEnvironment() == null
                        ? "{}" : new TreeMap<>(request.getEnvironment().getAttributes()),
                version, decision, matchedRuleId, reason, record.getSequence());

        return new EvaluationResult(decision, version, matchedRuleId, reason, record.getAuditId());
    }

    private void validateRequest(EvaluationRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("请求体为空");
        }
        if (isBlank(request.getSubjectId())) {
            throw new IllegalArgumentException("subjectId 缺失");
        }
        if (isBlank(request.getAction())) {
            throw new IllegalArgumentException("action 缺失");
        }
        if (isBlank(request.getResourceId())) {
            throw new IllegalArgumentException("resourceId 缺失");
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /** 关键上下文摘要：角色数/角色集合、资源类型与敏感级、环境键集合（不记录敏感值） */
    private String summarize(EvaluationRequest request, Subject subject, Resource resource) {
        StringBuilder sb = new StringBuilder();
        sb.append("subject=").append(subject == null ? "?" : subject.getSubjectId());
        sb.append(",roles=").append(subject == null ? "[]" : subject.getRoles());
        sb.append(";resourceType=").append(resource == null ? "?" : resource.getResourceType());
        sb.append(",sensitivity=").append(resource == null ? "?" : resource.getSensitivity());
        Map<String, String> env = request == null || request.getEnvironment() == null
                ? Map.of() : request.getEnvironment().getAttributes();
        sb.append(";envKeys=").append(new TreeMap<>(env).keySet());
        return sb.toString();
    }
}
