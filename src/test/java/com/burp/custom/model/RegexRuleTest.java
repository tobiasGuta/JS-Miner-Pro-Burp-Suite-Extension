package com.burp.custom.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

class RegexRuleTest {
    @Test
    void permitsNestedQuantifiersBecauseRe2jMatchesThemSafely() {
        RegexRule rule = new RegexRule(true, "Nested quantifier", "^(a+)+$", "INFO");

        assertNotNull(rule.getPattern());
        assertTrue(!rule.getPattern().matcher("a".repeat(20_000) + "!").find());
    }

    @Test
    void rejectsLookaroundsInsteadOfFallingBackToJavaRegex() {
        String error = RegexRule.validateRegex("(?<=prefix)token");

        assertNotNull(error);
        assertTrue(error.contains("RE2J"));
    }

    @Test
    void rejectsBackreferencesInsteadOfFallingBackToJavaRegex() {
        String error = RegexRule.validateRegex("(token)\\1");

        assertNotNull(error);
        assertTrue(error.contains("RE2J"));
    }

    @Test
    void acceptsRe2jCompatibleScanningRule() {
        assertNull(RegexRule.validateRegex("(?i)bearer\\s+([a-z0-9_-]{20,})"));
    }

    @Test
    void defaultsExistingRulesToNoEntropyPolicy() {
        RegexRule rule = new RegexRule(true, "Deterministic token", "token", "SECRET", "HIGH");

        assertEquals(EntropyPolicy.NONE, rule.getEntropyPolicy());
    }
}
