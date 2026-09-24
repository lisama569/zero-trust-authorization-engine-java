package com.github.lisama569.zerotrustauthorizationenginejava.model;

/** 资源：标识、类型与敏感级别（1 最低，5 最高） */
public final class Resource {
    private final String resourceId;
    private final String resourceType;
    private final int sensitivity;

    public Resource(String resourceId, String resourceType, int sensitivity) {
        this.resourceId = resourceId;
        this.resourceType = resourceType;
        this.sensitivity = sensitivity;
    }

    public String getResourceId() { return resourceId; }
    public String getResourceType() { return resourceType; }
    public int getSensitivity() { return sensitivity; }
}
