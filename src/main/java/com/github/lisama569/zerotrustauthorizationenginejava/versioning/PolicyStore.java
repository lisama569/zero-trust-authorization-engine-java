package com.github.lisama569.zerotrustauthorizationenginejava.versioning;

import com.github.lisama569.zerotrustauthorizationenginejava.model.Policy;
import com.github.lisama569.zerotrustauthorizationenginejava.validation.PolicyFailureCode;
import com.github.lisama569.zerotrustauthorizationenginejava.validation.PolicyValidationException;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 本地策略版本库。
 *
 * <p>并发模型：
 * <ul>
 *   <li>{@link #register} 写入 {@link ConcurrentHashMap} 注册表，重复版本被拒绝
 *       （{@link PolicyFailureCode#VERSION_ALREADY_EXISTS}）；</li>
 *   <li>{@link #publish}/{@link #rollback} 通过 {@link AtomicReference}
 *       原子替换当前不可变 {@link PolicyVersion} 快照，评估线程要么看到旧版本、
 *       要么看到新版本，绝不会混用两个版本的规则；</li>
 *   <li>注册顺序用 {@link ConcurrentSkipListMap} 保留，供版本列表展示。</li>
 * </ul>
 */
@Component
public class PolicyStore {

    private final Map<String, PolicyVersion> registry = new ConcurrentHashMap<>();
    private final NavigableMap<String, String> orderedVersions = new ConcurrentSkipListMap<>();
    private final AtomicReference<PolicyVersion> current = new AtomicReference<>();

    /**
     * 注册一个新版本（不改变当前生效版本）。
     *
     * @throws PolicyValidationException VERSION_ALREADY_EXISTS 版本已注册
     */
    public void register(Policy policy, String source) {
        PolicyVersion pv = new PolicyVersion(policy, Instant.now(), source);
        PolicyVersion existing = registry.putIfAbsent(policy.version(), pv);
        if (existing != null) {
            throw new PolicyValidationException(PolicyFailureCode.VERSION_ALREADY_EXISTS,
                    "策略版本已存在: " + policy.version());
        }
        orderedVersions.put(policy.version(), policy.version());
    }

    /**
     * 发布已注册版本，使其成为当前生效版本。
     *
     * @throws PolicyValidationException ROLLBACK_TARGET_NOT_FOUND 版本不存在
     */
    public void publish(String version) {
        PolicyVersion pv = registry.get(version);
        if (pv == null) {
            throw new PolicyValidationException(PolicyFailureCode.ROLLBACK_TARGET_NOT_FOUND,
                    "发布目标版本不存在: " + version);
        }
        current.set(pv);
    }

    /**
     * 回滚到任意已注册的历史版本（原子切换当前快照）。
     *
     * @throws PolicyValidationException ROLLBACK_TARGET_NOT_FOUND 回滚目标不存在
     */
    public void rollback(String version) {
        PolicyVersion pv = registry.get(version);
        if (pv == null) {
            throw new PolicyValidationException(PolicyFailureCode.ROLLBACK_TARGET_NOT_FOUND,
                    "回滚目标版本不存在: " + version);
        }
        current.set(pv);
    }

    /** 当前生效的不可变版本快照；启动初期可能为空。 */
    public Optional<PolicyVersion> current() {
        return Optional.ofNullable(current.get());
    }

    /** 按注册顺序返回全部已知版本号。 */
    public List<String> versions() {
        return List.copyOf(orderedVersions.keySet());
    }
}
