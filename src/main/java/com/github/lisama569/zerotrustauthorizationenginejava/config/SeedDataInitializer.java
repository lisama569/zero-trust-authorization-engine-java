package com.github.lisama569.zerotrustauthorizationenginejava.config;

import com.github.lisama569.zerotrustauthorizationenginejava.directory.LocalDirectory;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Effect;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Policy;
import com.github.lisama569.zerotrustauthorizationenginejava.model.PolicyRule;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Resource;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Subject;
import com.github.lisama569.zerotrustauthorizationenginejava.version.PolicyVersionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * 初始化本地模拟主体、资源目录与默认策略版本 v1.0.0。
 */
@Component
public class SeedDataInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(SeedDataInitializer.class);

    private final LocalDirectory directory;
    private final PolicyVersionManager versionManager;

    public SeedDataInitializer(LocalDirectory directory, PolicyVersionManager versionManager) {
        this.directory = directory;
        this.versionManager = versionManager;
    }

    @Override
    public void run(String... args) {
        directory.putSubject(new Subject("alice", List.of("engineer"),
                Map.of("department", "platform", "employment", "full-time")));
        directory.putSubject(new Subject("bob", List.of("auditor"),
                Map.of("department", "security", "employment", "full-time")));
        directory.putSubject(new Subject("carol", List.of("contractor"),
                Map.of("department", "external", "employment", "contract")));

        directory.putResource(new Resource("doc-public", "document", 1));
        directory.putResource(new Resource("doc-internal", "document", 3));
        directory.putResource(new Resource("doc-secret", "document", 5));
        directory.putResource(new Resource("server-prod-1", "server", 4));

        Policy defaultPolicy = new Policy("1.0.0", "1.0", List.of(
                new PolicyRule("r-allow-engineer-doc", "工程师可读中低敏感文档",
                        Effect.ALLOW, List.of("engineer"), "document", 3,
                        List.of("read"), Map.of()),
                new PolicyRule("r-allow-auditor-corp", "审计员在公司网络可读任意文档",
                        Effect.ALLOW, List.of("auditor"), "document", 5,
                        List.of("read"), Map.of("networkZone", "corp")),
                new PolicyRule("r-deny-contractor-secret", "外包禁止读机密文档",
                        Effect.DENY, List.of("contractor"), "document", 5,
                        List.of("read"), Map.of()),
                new PolicyRule("r-allow-engineer-deploy", "工程师用可信设备可部署低敏感服务器",
                        Effect.ALLOW, List.of("engineer"), "server", 2,
                        List.of("deploy"), Map.of("deviceTrust", "high"))
        ));
        versionManager.registerInitial(defaultPolicy, "种子默认策略");
        log.info("种子数据初始化完成，默认策略版本 1.0.0 已生效");
    }
}
