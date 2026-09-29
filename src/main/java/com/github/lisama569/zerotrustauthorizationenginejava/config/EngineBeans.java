package com.github.lisama569.zerotrustauthorizationenginejava.config;

import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLog;
import com.github.lisama569.zerotrustauthorizationenginejava.audit.FileAuditStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;

/** 引擎基础 Bean */
@Configuration
public class EngineBeans {

    private static final Logger log = LoggerFactory.getLogger(EngineBeans.class);

    /**
     * 文件持久化审计日志。Bean 创建时先把历史记录整体读回并复核哈希链：
     * 本地文件被改过/插入/删除/截断会直接让启动失败（fail-closed），
     * 绝不带着不可信的审计状态继续服务。
     */
    @Bean
    public AuditLog auditLog(
            @Value("${audit.file.records:./data/audit/audit-records.jsonl}") String recordsPath,
            @Value("${audit.file.checkpoint:./data/audit/audit-checkpoint.json}") String checkpointPath) {
        FileAuditStore store = new FileAuditStore(Path.of(recordsPath), Path.of(checkpointPath));
        AuditLog auditLog = new AuditLog(store);
        int recovered = auditLog.recoverFromStore();
        if (recovered > 0) {
            log.info("审计历史恢复并复核通过，共 {} 条记录", recovered);
        }
        return auditLog;
    }
}
