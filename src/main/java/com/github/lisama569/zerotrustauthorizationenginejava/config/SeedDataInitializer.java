package com.github.lisama569.zerotrustauthorizationenginejava.config;

import com.github.lisama569.zerotrustauthorizationenginejava.directory.LocalDirectory;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AttributeCondition;
import com.github.lisama569.zerotrustauthorizationenginejava.model.AttributeOperator;
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
 * 初始化本地模拟主体、资源目录与默认策略版本。
 * 当前生效版本保持为 1.0.0（仅角色/资源/环境维度）；
 * 另登记 1.1.0 演示“角色 + 主体属性条件”，可随时发布切换/回滚，
 * 两个版本相同输入的结论各自稳定，老版本行为不因扩展改变。
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
                Map.of("department", "platform", "employment", "full-time",
                        "clearanceLevel", "4")));
        directory.putSubject(new Subject("bob", List.of("auditor"),
                Map.of("department", "security", "employment", "full-time",
                        "clearanceLevel", "5")));
        directory.putSubject(new Subject("carol", List.of("contractor"),
                Map.of("department", "external", "employment", "contract",
                        "clearanceLevel", "1")));

        directory.putResource(new Resource("doc-public", "document", 1));
        directory.putResource(new Resource("doc-internal", "document", 3));
        directory.putResource(new Resource("doc-secret", "document", 5));
        directory.putResource(new Resource("server-prod-1", "server", 4));

        Policy v1 = new Policy("1.0.0", "1.0", List.of(
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
        versionManager.registerInitial(v1, "种子默认策略（仅角色/资源/环境）");

        // 1.1.0：在角色之外叠加主体属性条件（相等/集合/不等/数值比较）
        Policy v11 = new Policy("1.1.0", "1.1", List.of(
                new PolicyRule("r-allow-engineer-ft-platform",
                        "平台部门全职工程师可读任意文档",
                        Effect.ALLOW, List.of("engineer"), "document", 5,
                        List.of("read"), Map.of(),
                        List.of(
                                new AttributeCondition("employment", AttributeOperator.EQ,
                                        List.of("full-time")),
                                new AttributeCondition("department", AttributeOperator.EQ,
                                        List.of("platform")))),
                new PolicyRule("r-allow-auditor-security-corp",
                        "安全部门审计员在公司网络可读任意文档",
                        Effect.ALLOW, List.of("auditor"), "document", 5,
                        List.of("read"), Map.of("networkZone", "corp"),
                        List.of(new AttributeCondition("department", AttributeOperator.IN,
                                List.of("security", "compliance")))),
                new PolicyRule("r-deny-nonfulltime-secret",
                        "非全职人员读机密一律拒绝",
                        Effect.DENY, List.of("contractor"), "document", 5,
                        List.of("read"), Map.of(),
                        List.of(new AttributeCondition("employment", AttributeOperator.NOT_IN,
                                List.of("full-time")))),
                new PolicyRule("r-allow-engineer-deploy-clearance",
                        "高许可等级工程师用可信设备可部署低敏感服务器",
                        Effect.ALLOW, List.of("engineer"), "server", 2,
                        List.of("deploy"), Map.of("deviceTrust", "high"),
                        List.of(new AttributeCondition("clearanceLevel", AttributeOperator.GTE,
                                List.of("3"))))
        ));
        if (!versionManager.hasVersion("1.1.0")) {
            versionManager.registerInitial(v11, "种子策略（角色 + 主体属性条件）");
        }
        log.info("种子数据初始化完成，当前生效策略 1.0.0，并已登记可切换的 1.1.0 属性条件版本");
    }
}
