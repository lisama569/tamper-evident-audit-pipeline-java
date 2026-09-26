package com.github.lisama569.tamperevidentauditpipelinejava.tests;

import com.github.lisama569.tamperevidentauditpipelinejava.domain.ErrorClass;
import com.github.lisama569.tamperevidentauditpipelinejava.domain.StoredRecord;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.AuditForwarder;
import com.github.lisama569.tamperevidentauditpipelinejava.forward.ForwarderResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 可编程假转发器：按脚本返回成功/可重试失败/不可重试失败，
 * 并记录每个 recordId 的投递次数，用于断言“不重复、不丢失、幂等”。
 */
class ScriptedForwarder implements AuditForwarder {

    /** 对某 seq 的脚本：按调用次序返回结果；耗尽后默认成功。 */
    private final ConcurrentHashMap<Long, List<ForwarderResponse>> scripts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicInteger> deliveryCount = new ConcurrentHashMap<>();
    /** 实际送达（收到成功 ACK）的 recordId，按顺序。 */
    private final List<String> deliveredRecordIds = java.util.Collections.synchronizedList(new ArrayList<>());

    ScriptedForwarder failThenOk(long seq, int failures, ErrorClass cls) {
        List<ForwarderResponse> l = new ArrayList<>();
        for (int i = 0; i < failures; i++) {
            l.add(ForwarderResponse.failure(cls, cls.name(), "scripted-" + cls + "-" + i));
        }
        l.add(ForwarderResponse.ok());
        scripts.put(seq, l);
        return this;
    }

    ScriptedForwarder alwaysFail(long seq, ErrorClass cls) {
        scripts.put(seq, List.of(ForwarderResponse.failure(cls, cls.name(), "permanent-" + cls)));
        return this;
    }

    int deliveryCountOf(String recordId) {
        AtomicInteger a = deliveryCount.get(recordId);
        return a == null ? 0 : a.get();
    }

    List<String> deliveredRecordIds() {
        synchronized (deliveredRecordIds) {
            return new ArrayList<>(deliveredRecordIds);
        }
    }

    @Override
    public ForwarderResponse forward(StoredRecord record) {
        int n = deliveryCount.computeIfAbsent(record.recordId(), k -> new AtomicInteger()).incrementAndGet();
        List<ForwarderResponse> script = scripts.get(record.seq());
        ForwarderResponse resp;
        if (script == null) {
            resp = ForwarderResponse.ok();
        } else {
            int idx = Math.min(n - 1, script.size() - 1);
            resp = script.get(idx);
        }
        if (resp.success()) {
            deliveredRecordIds.add(record.recordId());
        }
        return resp;
    }
}
