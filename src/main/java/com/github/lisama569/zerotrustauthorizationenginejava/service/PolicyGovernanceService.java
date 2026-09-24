package com.github.lisama569.zerotrustauthorizationenginejava.service;

import com.github.lisama569.zerotrustauthorizationenginejava.model.Policy;
import com.github.lisama569.zerotrustauthorizationenginejava.model.PublishedPolicy;
import com.github.lisama569.zerotrustauthorizationenginejava.policy.PolicyParser;
import com.github.lisama569.zerotrustauthorizationenginejava.version.PolicyVersionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 策略治理门面：解析 -> 校验 -> 发布，以及回滚/查询。
 * 非法策略、冲突规则、未知字段、不存在的回滚目标都会以
 * 携带 FailureReason 的 PolicyException 返回，绝不静默接受。
 */
@Service
public class PolicyGovernanceService {

    private static final Logger log = LoggerFactory.getLogger(PolicyGovernanceService.class);

    private final PolicyParser parser;
    private final PolicyVersionManager versionManager;

    public PolicyGovernanceService(PolicyParser parser, PolicyVersionManager versionManager) {
        this.parser = parser;
        this.versionManager = versionManager;
    }

    public PublishedPolicy publishJson(String json, String note) {
        Policy policy = parser.parse(json);
        PublishedPolicy snapshot = versionManager.publish(policy, note);
        log.info("策略发布成功 version={} ruleCount={} note='{}'",
                policy.getPolicyVersion(), policy.getRules().size(), note);
        return snapshot;
    }

    public PublishedPolicy rollback(String targetVersion) {
        PublishedPolicy snapshot = versionManager.rollback(targetVersion);
        log.info("策略回滚成功 version={} ruleCount={}",
                snapshot.getPolicy().getPolicyVersion(),
                snapshot.getPolicy().getRules().size());
        return snapshot;
    }

    public PublishedPolicy current() {
        return versionManager.current();
    }

    public List<String> history() {
        return versionManager.historyVersions();
    }
}
