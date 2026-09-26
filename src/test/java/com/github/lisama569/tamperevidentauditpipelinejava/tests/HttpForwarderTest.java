package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.github.lisama569.tamperevidentauditpipelinejava.forward.Forwarder.ForwardResult;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.HttpForwarder;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.OutboxEntry;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.ForwardOutcome;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * HttpForwarder 错误类别归类：4xx(非408/429) 不可重试；429/5xx 可重试；连接拒绝可重试；未配置不可重试。
 */
class HttpForwarderTest {

    private static final Logger LOG = Logger.getLogger(HttpForwarderTest.class.getName());

    private OutboxEntry entry() {
        return new OutboxEntry(1, 1, "k", "{}", OutboxEntry.PENDING, 0, 0L, 0L, null);
    }

    @Test
    void classifyStatusCodes(TestInfo info) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/c", ex -> {
            ex.getRequestBody().readAllBytes();
            int code = Integer.parseInt(ex.getRequestURI().getQuery().substring(5));
            ex.sendResponseHeaders(code, -1);
            ex.close();
        });
        server.start();
        try {
            String base = "http://localhost:" + server.getAddress().getPort() + "/c?code=";
            assertEquals(ForwardOutcome.SUCCESS, new HttpForwarder(base + "200", HttpClient.newHttpClient(), 5000).forward(entry()).outcome());
            assertEquals(ForwardOutcome.RETRYABLE, new HttpForwarder(base + "429", HttpClient.newHttpClient(), 5000).forward(entry()).outcome());
            assertEquals(ForwardOutcome.RETRYABLE, new HttpForwarder(base + "503", HttpClient.newHttpClient(), 5000).forward(entry()).outcome());
            assertEquals(ForwardOutcome.RETRYABLE, new HttpForwarder(base + "408", HttpClient.newHttpClient(), 5000).forward(entry()).outcome());
            ForwardResult r404 = new HttpForwarder(base + "404", HttpClient.newHttpClient(), 5000).forward(entry());
            assertEquals(ForwardOutcome.NON_RETRYABLE, r404.outcome());
            assertEquals("HTTP_404", r404.errorCategory());
            LOG.info(() -> "[CASE " + info.getDisplayName()
                    + "] 判定依据=200成功/429,503,408可重试/404不可重试 最终状态=错误归类正确且类别可区分");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void classifyConnectionFailure(TestInfo info) {
        // 端口 1 通常无服务：连接失败必须归为可重试网络错误
        HttpForwarder f = new HttpForwarder("http://localhost:1/hook", HttpClient.newHttpClient(), 1500);
        ForwardResult r = f.forward(entry());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 判定依据=" + r.errorCategory()
                + " 最终状态=" + r.outcome());
        assertEquals(ForwardOutcome.RETRYABLE, r.outcome());
    }

    @Test
    void classifyMissingConfig(TestInfo info) {
        HttpForwarder f = new HttpForwarder("", HttpClient.newHttpClient(), 1000);
        ForwardResult r = f.forward(entry());
        assertEquals(ForwardOutcome.NON_RETRYABLE, r.outcome());
        assertEquals("NOT_CONFIGURED", r.errorCategory());
        LOG.info(() -> "[CASE " + info.getDisplayName() + "] 最终状态=未配置地址归为不可重试死信，不空转");
    }
}
