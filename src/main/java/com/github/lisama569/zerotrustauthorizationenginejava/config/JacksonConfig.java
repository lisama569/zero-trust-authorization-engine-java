package com.github.lisama569.zerotrustauthorizationenginejava.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * HTTP 层 Jackson 定制：请求体出现引擎不认识的字段一律反序列化失败，
 * 绝不静默忽略，由全局异常处理映射为可区分的 UNKNOWN_FIELD。
 */
@Configuration
public class JacksonConfig {

    @Bean
    public Jackson2ObjectMapperBuilderCustomizer failOnUnknownPropertiesCustomizer() {
        return builder -> builder.featuresToEnable(
                DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }
}
