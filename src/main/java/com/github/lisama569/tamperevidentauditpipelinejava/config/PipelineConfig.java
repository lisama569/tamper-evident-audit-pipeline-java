package com.github.lisama569.tamperevidentauditpipelinejava.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.HmacSigner;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.AuditForwarder;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.HttpAuditForwarder;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.LoggingForwarder;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.OutboxStore;
import com.github.lisama569.tamperevidentauditpipelinejava.retention.LegalHoldStore;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.CompactionJournal;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.FileAppendStore;
import com.github.lisama569.tamperevidentauditpipelinejava.storage.TamperEvidentStore;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;

/**
 * Bean 装配与启动顺序。
 *
 * <p>初始化顺序（在 {@link PipelineBootstrap} 中严格执行）：
 * 存储校验 → 压实凭证 → 法律保留 → outbox，任何一环校验失败都快速失败（拒绝启动），
 * 避免在“留存完整性未知”的状态下对外提供服务。
 */
@Configuration
@EnableConfigurationProperties(PipelineProperties.class)
public class PipelineConfig {

    @Bean
    public HmacSigner hmacSigner(PipelineProperties props) {
        return new HmacSigner(props.getHmacSecret());
    }

    @Bean
    public ObjectMapper auditObjectMapper() {
        ObjectMapper m = new ObjectMapper();
        m.registerModule(new JavaTimeModule());
        m.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return m;
    }

    @Bean
    public Path auditStorageDir(PipelineProperties props) {
        return Path.of(props.getStorageDir());
    }

    @Bean(initMethod = "initialize")
    public FileAppendStore fileAppendStore(Path auditStorageDir,
                                           HmacSigner signer,
                                           ObjectMapper auditObjectMapper) {
        return new FileAppendStore(auditStorageDir, signer, auditObjectMapper);
    }

    @Bean
    @org.springframework.context.annotation.Primary
    public TamperEvidentStore tamperEvidentStore(FileAppendStore impl) {
        return impl;
    }

    @Bean(initMethod = "initialize")
    public CompactionJournal compactionJournal(Path auditStorageDir,
                                               ObjectMapper auditObjectMapper,
                                               HmacSigner signer) {
        return new CompactionJournal(auditStorageDir, auditObjectMapper, signer);
    }

    @Bean(initMethod = "initialize")
    public LegalHoldStore legalHoldStore(Path auditStorageDir,
                                         ObjectMapper auditObjectMapper,
                                         HmacSigner signer) {
        return new LegalHoldStore(auditStorageDir, auditObjectMapper, signer);
    }

    @Bean(initMethod = "initialize")
    public OutboxStore outboxStore(Path auditStorageDir, ObjectMapper auditObjectMapper) {
        return new OutboxStore(auditStorageDir, auditObjectMapper);
    }

    @Bean
    public AuditForwarder auditForwarder(PipelineProperties props, ObjectMapper auditObjectMapper) {
        if (props.getForwarderUrl() == null || props.getForwarderUrl().isBlank()) {
            return new LoggingForwarder();
        }
        return new HttpAuditForwarder(props.getForwarderUrl(),
                props.getForwardConnectTimeoutMs(),
                props.getForwardReadTimeoutMs(),
                auditObjectMapper);
    }
}
