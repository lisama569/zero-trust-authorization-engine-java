package com.github.lisama569.zerotrustauthorizationenginejava.bootstrap;

import com.github.lisama569.zerotrustauthorizationenginejava.model.Effect;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Policy;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Rule;
import com.github.lisama569.zerotrustauthorizationenginejava.validation.PolicyValidator;
import com.github.lisama569.zerotrustauthorizationenginejava.versioning.PolicyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 启动播种：注册并发布内置 v0-bootstrap 策略。
 *
 * <p>该版本仅含一条无条件（条件列表为空，恒匹配）兜底拒绝规则，
 * 保证系统在未加载任何业务策略前即处于"显式默认拒绝"状态，绝不裸奔放行；
 * 且结论是 DENY（而非 POLICY_NOT_MATCHED），对外语义明确。
 * 播种幂等：版本已存在时只确保其为当前版本。
 */
@Component
@Order(0)
public class DefaultPolicySeed implements ApplicationRunner {

    /** 内置引导策略版本号。 */
    public static final String BOOTSTRAP_VERSION = "v0-bootstrap";

    private static final Logger log = LoggerFactory.getLogger(DefaultPolicySeed.class);

    private final PolicyStore policyStore;
    private final PolicyValidator validator;

    public DefaultPolicySeed(PolicyStore policyStore, PolicyValidator validator) {
        this.policyStore = policyStore;
        this.validator = validator;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (policyStore.current().isPresent()) {
            return;
        }
        Rule denyAll = new Rule("bootstrap-deny-all", Effect.DENY, List.of());
        Policy bootstrap = new Policy(
                1, "root-policy", BOOTSTRAP_VERSION, List.of(denyAll));
        validator.validate(bootstrap);
        if (!policyStore.versions().contains(BOOTSTRAP_VERSION)) {
            policyStore.register(bootstrap, "bootstrap");
        }
        policyStore.publish(BOOTSTRAP_VERSION);
        log.info("内置引导策略已播种并发布: {}", BOOTSTRAP_VERSION);
    }
}
