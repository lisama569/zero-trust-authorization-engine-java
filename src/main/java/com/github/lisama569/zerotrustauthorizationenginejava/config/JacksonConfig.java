package com.github.lisama569.zerotrustauthorizationenginejava.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Jackson 全局配置。
 *
 * <p>开启 FAIL_ON_UNKNOWN_PROPERTIES：请求 DTO（如 AccessRequest）中出现未声明字段时
 * 直接失败，而不是静默忽略。策略 JSON 的未知字段由
 * {@link com.github.lisama569.zerotrustauthorizationenginejava.validation.PolicyParser}
 * 做更精细的逐字段收集与报错。
 */
@Configuration
public class JacksonConfig {

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper()
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT);
    }
}
