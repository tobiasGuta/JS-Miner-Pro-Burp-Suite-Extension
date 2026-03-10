package com.burp.custom.model;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class RegexRule {
    private boolean active;
    private String name;
    private String regex;
    private String type; // "PATH", "SECRET", "ENDPOINT", "URL", "INFO", "FILE"
    private String severity; // "HIGH", "MEDIUM", "LOW", "INFO"
    private transient Pattern pattern;
    private transient boolean patternInvalid = false;
    private transient String patternError = null;

    public RegexRule(boolean active, String name, String regex, String type) {
        this(active, name, regex, type, determineSeverity(type));
    }

    public RegexRule(boolean active, String name, String regex, String type, String severity) {
        this.active = active;
        this.name = name;
        this.regex = regex;
        this.type = type;
        this.severity = severity != null ? severity : determineSeverity(type);
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
        try {
            Pattern.compile(regex);
            return null;
        } catch (PatternSyntaxException e) {
            return e.getMessage();
        }
    }

    public boolean isPatternInvalid() { return patternInvalid; }
    public String getPatternError() { return patternError; }
}