package com.github.lisama569.zerotrustauthorizationenginejava.validation;

/** 策略处理过程中可区分的失败原因。 */
public enum PolicyFailureCode {
    MALFORMED_JSON,
    UNKNOWN_FIELD,
    SCHEMA_VERSION_INCOMPATIBLE,
    MISSING_REQUIRED_FIELD,
    INVALID_ENUM_VALUE,
    INVALID_RULE_REFERENCE,
    DUPLICATE_RULE_ID,
    CONFLICTING_RULES,
    VERSION_ALREADY_EXISTS,
    ROLLBACK_TARGET_NOT_FOUND,
    NO_PUBLISHED_POLICY
}
