package com.github.lisama569.tamperevidentauditpipelinejava.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.tamperevidentauditpipelinejava.service.AuditPipelineService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring 装配：确定性 JSON（不输出时间戳为日期对象，保持字段顺序）与流水线门面。
 */
@Configuration
@EnableConfigurationProperties(PipelineProperties.class)
public class PipelineConfig {

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    @Bean(destroyMethod = "close")
    public AuditPipelineService auditPipelineService(PipelineProperties props, ObjectMapper mapper) {
        return new AuditPipelineService(props, mapper);
    }
}
