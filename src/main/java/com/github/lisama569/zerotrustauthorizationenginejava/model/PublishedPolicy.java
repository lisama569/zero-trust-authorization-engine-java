package com.github.lisama569.zerotrustauthorizationenginejava.model;

/** 已发布策略版本快照（不可变），供评估原子引用 */
public final class PublishedPolicy {
    private final Policy policy;
    private final long publishedAt;
    private final String note;

    public PublishedPolicy(Policy policy, long publishedAt, String note) {
        this.policy = policy;
        this.publishedAt = publishedAt;
        this.note = note;
    }

    public Policy getPolicy() { return policy; }
    public long getPublishedAt() { return publishedAt; }
    public String getNote() { return note; }
}
