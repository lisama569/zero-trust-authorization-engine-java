package com.github.lisama569.zerotrustauthorizationenginejava.config;

import com.github.lisama569.zerotrustauthorizationenginejava.audit.AuditLog;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** 引擎基础 Bean */
@Configuration
public class EngineBeans {

    @Bean
    public AuditLog auditLog() {
        return new AuditLog();
    }
}
