package com.burp.custom.model;

import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;

public class RegexRule {
    private boolean active;
    private String name;
    private String regex;
    private String type; // "PATH", "SECRET", "ENDPOINT", "URL", "INFO", "FILE"
    private String severity; // "HIGH", "MEDIUM", "LOW", "INFO"
    private EntropyPolicy entropyPolicy;
    private transient Pattern pattern;
    private transient boolean patternInvalid = false;
    private transient String patternError = null;

    public RegexRule(boolean active, String name, String regex, String type) {
        this(active, name, regex, type, determineSeverity(type));
    }

    public RegexRule(boolean active, String name, String regex, String type, String severity) {
        this(active, name, regex, type, severity, EntropyPolicy.NONE);
    }

    public RegexRule(boolean active, String name, String regex, String type, String severity, EntropyPolicy entropyPolicy) {
        this.active = active;
        this.name = name;
        this.regex = regex;
        this.type = type;
        this.severity = severity != null ? severity : determineSeverity(type);
        this.entropyPolicy = entropyPolicy != null ? entropyPolicy : EntropyPolicy.NONE;
    }

    /**
     * Determines default severity based on finding type
     */
    private static String determineSeverity(String type) {
        if (type == null) return "INFO";
        switch (type.toUpperCase()) {
            case "SECRET":
                return "HIGH";
            case "URL":
            case "ENDPOINT":
                return "MEDIUM";
            case "FILE":
                return "LOW";
            default:
                return "INFO";
        }
    }

    // Getters and Setters
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getRegex() { return regex; }
    public void setRegex(String regex) { 
        this.regex = regex;
        // Reset pattern cache when regex changes
        this.pattern = null;
        this.patternInvalid = false;
        this.patternError = null;
    }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getSeverity() { return severity != null ? severity : determineSeverity(type); }
    public void setSeverity(String severity) { this.severity = severity; }
    public EntropyPolicy getEntropyPolicy() { return entropyPolicy != null ? entropyPolicy : EntropyPolicy.NONE; }
    public void setEntropyPolicy(EntropyPolicy entropyPolicy) {
        this.entropyPolicy = entropyPolicy != null ? entropyPolicy : EntropyPolicy.NONE;
    }

    /**
     * Returns the compiled pattern, or null if the regex is invalid.
     * Uses Pattern.MULTILINE for better matching in minified JS.
     */
    public Pattern getPattern() {
        if (patternInvalid) {
            return null;
        }
        if (pattern == null) {
            try {
                if (regex == null) {
                    patternInvalid = true;
                    patternError = "Regex cannot be null";
                    return null;
                }
                if (regex.length() > 500) {
                    patternInvalid = true;
                    patternError = "Regex is too long; split it into smaller rules";
                    return null;
                }
                pattern = Pattern.compile(regex, Pattern.MULTILINE);
                patternInvalid = false;
                patternError = null;
            } catch (PatternSyntaxException e) {
                patternInvalid = true;
                patternError = e.getMessage();
                return null;
            }
        }
        return pattern;
    }

    /**
     * Validates the regex without caching the result.
     * @return null if valid, error message if invalid
     */
    public static String validateRegex(String regex) {
        if (regex == null) return "Regex cannot be null";
        if (regex.length() > 500) return "Regex is too long; split it into smaller rules";
        try {
            Pattern.compile(regex, Pattern.MULTILINE);
            return null;
        } catch (PatternSyntaxException e) {
            return "Unsupported or invalid RE2J regex: " + e.getMessage();
        }
    }

    public boolean isPatternInvalid() { return patternInvalid; }
    public String getPatternError() { return patternError; }
}
