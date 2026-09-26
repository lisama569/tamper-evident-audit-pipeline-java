package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Path;

/**
 * 上下文装配冒烟测试：使用独立临时目录，不在工程内留下数据。
 */
@SpringBootTest
public class ApplicationTests {

    @org.junit.jupiter.api.io.TempDir
    static Path tempDir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("audit.storage-dir", () -> tempDir.toString());
        registry.add("audit.auto-forward", () -> "false");
    }

    @Test
    public void contextLoads() {
    }
}
