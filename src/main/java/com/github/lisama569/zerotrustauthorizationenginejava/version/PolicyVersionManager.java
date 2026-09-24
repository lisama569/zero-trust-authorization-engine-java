package com.github.lisama569.zerotrustauthorizationenginejava.version;

import com.github.lisama569.zerotrustauthorizationenginejava.exception.PolicyException;
import com.github.lisama569.zerotrustauthorizationenginejava.model.FailureReason;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Policy;
import com.github.lisama569.zerotrustauthorizationenginejava.model.PublishedPolicy;
import com.github.lisama569.zerotrustauthorizationenginejava.policy.PolicyValidator;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 策略版本管理器。
 *
 * 版本注册表保留所有已发布快照（只增不删，因此任意历史版本都可回滚）；
 * current 为 AtomicReference，发布/回滚是一次原子引用切换。
 * 评估侧在请求开始时读取一次引用并贯穿全程，切换期间的请求
 * 只会使用旧版本或新版本的完整规则，不会混用。
 */
@Component
public class PolicyVersionManager {

    private final PolicyValidator validator;
    private final Map<String, PublishedPolicy> registry = new ConcurrentHashMap<>();
    private final List<String> publishOrder = java.util.Collections.synchronizedList(new ArrayList<>());
    private final AtomicReference<PublishedPolicy> current = new AtomicReference<>();

    public PolicyVersionManager(PolicyValidator validator) {
        this.validator = validator;
    }

    /** 校验并发布新版本；非法/冲突/重复版本一律拒绝。 */
    public PublishedPolicy publish(Policy policy, String note) {
        validator.validate(policy);
        String version = policy.getPolicyVersion();
        if (registry.containsKey(version)) {
            throw new PolicyException(FailureReason.INVALID_POLICY,
                    "策略版本已存在，禁止重复发布: " + version);
        }
        PublishedPolicy snapshot = new PublishedPolicy(policy, System.currentTimeMillis(), note);
        // putIfAbsent 防止并发下同版本双双进入
        PublishedPolicy existing = registry.putIfAbsent(version, snapshot);
        if (existing != null) {
            throw new PolicyException(FailureReason.INVALID_POLICY,
                    "策略版本已存在（并发发布）: " + version);
        }
        publishOrder.add(version);
        current.set(snapshot);
        return snapshot;
    }

    /** 直接登记种子策略（启动初始化用，跳过“版本唯一”以外的重复检查外的正常流程） */
    public PublishedPolicy registerInitial(Policy policy, String note) {
        validator.validate(policy);
        PublishedPolicy snapshot = new PublishedPolicy(policy, System.currentTimeMillis(), note);
        registry.put(policy.getPolicyVersion(), snapshot);
        publishOrder.add(policy.getPolicyVersion());
        current.compareAndSet(null, snapshot);
        return snapshot;
    }

    /** 回滚到已发布过的版本；目标不存在 -> VERSION_NOT_FOUND。 */
    public PublishedPolicy rollback(String targetVersion) {
        if (targetVersion == null || targetVersion.isBlank()) {
            throw new PolicyException(FailureReason.VERSION_NOT_FOUND, "回滚目标版本为空");
        }
        PublishedPolicy snapshot = registry.get(targetVersion);
        if (snapshot == null) {
            throw new PolicyException(FailureReason.VERSION_NOT_FOUND,
                    "回滚目标版本不存在: " + targetVersion);
        }
        current.set(snapshot);
        return snapshot;
    }

    /** 当前生效快照（不可变引用，可能为 null：尚无策略） */
    public PublishedPolicy current() {
        return current.get();
    }

    public List<String> historyVersions() {
        synchronized (publishOrder) {
            return new ArrayList<>(publishOrder);
        }
    }

    public boolean hasVersion(String version) {
        return registry.containsKey(version);
    }
}
