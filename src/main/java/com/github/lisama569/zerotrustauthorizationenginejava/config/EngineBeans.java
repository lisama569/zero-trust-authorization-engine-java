package com.github.lisama569.zerotrustauthorizationenginejava.config;

import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLog;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditStore;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.FileAuditStore;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.InMemoryAuditStore;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;

/** 引擎基础 Bean：审计日志（默认 JSONL 文件持久化，可配置为内存模式） */
@Configuration
public class EngineBeans {

    private static final Logger log = LoggerFactory.getLogger(EngineBeans.class);

    /** 审计文件路径；设为 "in-memory" 关闭持久化（重启即丢） */
    @Value("${audit.file.path:data/audit-records.jsonl}")
    private String auditFilePath;

    @Bean
    public AuditLog auditLog() {
        AuditStore store;
        if ("in-memory".equalsIgnoreCase(auditFilePath)) {
            log.warn("审计持久化被关闭（audit.file.path=in-memory），重启后审计记录将丢失");
            store = new InMemoryAuditStore();
        } else {
            store = new FileAuditStore(Path.of(auditFilePath));
        }
        AuditLog auditLog = new AuditLog(store);
        // 构造期立即重放，保证 Bean 可用时历史记录已恢复
        auditLog.loadFromPersistence();
        return auditLog;
    }

    @PostConstruct
    void noteConfig() {
        log.info("审计存储配置 audit.file.path={}", auditFilePath);
    }
}
