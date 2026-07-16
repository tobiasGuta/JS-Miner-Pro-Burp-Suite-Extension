package com.burp.custom.model;

/** Controls whether entropy is relevant to a rule's match confidence. */
public enum EntropyPolicy {
    NONE,
    REQUIRE_MINIMUM,
    ADJUST_SEVERITY
}
