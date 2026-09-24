package com.github.lisama569.zerotrustauthorizationenginejava.engine;

import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLogger;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AccessRequest;
import com.github.lisama569.zerotrustauthorizationenginejava.model.DecisionOutcome;
import com.github.lisama569.zerotrustauthorizationenginejava.model.DecisionResult;
import com.github.lisama569.zerotrustauthorizationenginejava.validation.PolicyFailureCode;
import com.github.lisama569.zerotrustauthorizationenginejava.versioning.PolicyStore;
import com.github.lisama569.zerotrustauthorizationenginejava.versioning.PolicyVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

/**
 * 授权入口。
 *
 * <p>关键语义：
 * <ul>
 *   <li>评估开始时一次性获取当前策略版本快照（不可变对象引用），
 *       即使评估途中发生发布/回滚，本次请求仍全程使用同一版本，绝不混用规则；</li>
 *   <li>没有任何已发布策略时返回 EVALUATION_FAILED（可区分原因 NO_PUBLISHED_POLICY），
 *       不凭空放行；</li>
 *   <li>任何内部异常都被转换为 EVALUATION_FAILED 对外结果，异常细节只进日志；</li>
 *   <li>每次评估（含失败）都写审计，审计中记录实际生效版本。</li>
 * </ul>
 */
@Service
public class AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationService.class);

    private final PolicyStore policyStore;
    private final Evaluator evaluator;
    private final AuditLogger auditLogger;

    public AuthorizationService(PolicyStore policyStore,
                                Evaluator evaluator,
                                AuditLogger auditLogger) {
        this.policyStore = policyStore;
        this.evaluator = evaluator;
        this.auditLogger = auditLogger;
    }

    public DecisionResult authorize(AccessRequest request, String requestId) {
        String effectiveRequestId = (requestId == null || requestId.isBlank())
                ? UUID.randomUUID().toString() : requestId;
        DecisionResult result;
        try {
            Optional<PolicyVersion> snapshot = policyStore.current();
            if (snapshot.isEmpty()) {
                result = new DecisionResult(
                        DecisionOutcome.EVALUATION_FAILED,
                        "none",
                        null,
                        "当前没有已发布策略（" + PolicyFailureCode.NO_PUBLISHED_POLICY
                                + "），按失败关闭处理");
            } else {
                PolicyVersion version = snapshot.get();
                // 整个评估只使用 version 这一个不可变快照。
                result = evaluator.evaluate(version.policy(), request, effectiveRequestId);
            }
        } catch (Exception e) {
            log.error("授权入口内部异常 requestId={}", effectiveRequestId, e);
            result = new DecisionResult(
                    DecisionOutcome.EVALUATION_FAILED,
                    "unknown",
                    null,
                    "授权评估发生内部错误，细节见服务日志");
        }

        try {
            auditLogger.append(request, result, effectiveRequestId);
        } catch (Exception auditError) {
            // 审计写入失败不能改变已做出的授权结论，但必须显式告警。
            log.error("审计记录写入失败 requestId={}，授权结论仍为 {}",
                    effectiveRequestId, result.outcome(), auditError);
        }
        return result;
    }
}
