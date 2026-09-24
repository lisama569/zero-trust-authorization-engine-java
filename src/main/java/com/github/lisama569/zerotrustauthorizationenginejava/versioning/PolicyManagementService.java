package com.github.lisama569.zerotrustauthorizationenginejava.versioning;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Policy;
import com.github.lisama569.zerotrustauthorizationenginejava.validation.PolicyParser;
import com.github.lisama569.zerotrustauthorizationenginejava.validation.PolicyValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 策略生命周期编排：加载(JSON) -> 严格解析 -> 语义校验 -> 注册 -> 发布/回滚。
 *
 * <p>解析或校验失败的策略不会进入版本库，调用方通过
 * {@link com.github.lisama569.zerotrustauthorizationenginejava.validation.PolicyValidationException}
 * 的 failureCode 区分失败原因。
 */
@Service
public class PolicyManagementService {

    private static final Logger log = LoggerFactory.getLogger(PolicyManagementService.class);

    private final PolicyParser parser;
    private final PolicyValidator validator;
    private final PolicyStore store;

    public PolicyManagementService(PolicyParser parser,
                                   PolicyValidator validator,
                                   PolicyStore store) {
        this.parser = parser;
        this.validator = validator;
        this.store = store;
    }

    /** 加载、校验并注册策略；不自动发布。返回解析后的不可变策略。 */
    public Policy loadAndRegister(JsonNode root, String source) {
        Policy policy = parser.parse(root);
        validator.validate(policy);
        store.register(policy, source);
        log.info("策略已注册: policyId={}, version={}, rules={}, source={}",
                policy.policyId(), policy.version(), policy.rules().size(), source);
        return policy;
    }

    /** 发布指定已注册版本。 */
    public void publish(String version) {
        store.publish(version);
        log.info("策略已发布: version={}", version);
    }

    /** 回滚到指定已注册历史版本。 */
    public void rollback(String version) {
        store.rollback(version);
        log.info("策略已回滚: version={}", version);
    }
}
