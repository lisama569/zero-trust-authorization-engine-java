package com.github.lisama569.zerotrustauthorizationenginejava.model;

import java.util.List;

/** 策略内容（不可变）：版本号、schema 版本、有序规则列表 */
public final class Policy {
    private final String policyVersion;
    private final String schemaVersion;
    private final List<PolicyRule> rules;

    public Policy(String policyVersion, String schemaVersion, List<PolicyRule> rules) {
        this.policyVersion = policyVersion;
        this.schemaVersion = schemaVersion;
        this.rules = rules;
    }

    public String getPolicyVersion() { return policyVersion; }
    public String getSchemaVersion() { return schemaVersion; }
    public List<PolicyRule> getRules() { return rules; }
}
