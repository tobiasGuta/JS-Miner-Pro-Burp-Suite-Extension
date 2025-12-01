package com.burp.custom.model;

public class RegexRule {
    private boolean active;
    private String name;
    private String regex;
    private String type; // "PATH" or "SECRET"

    public RegexRule(boolean active, String name, String regex, String type) {
        this.active = active;
        this.name = name;
        this.regex = regex;
        this.type = type;
    }

    // Getters and Setters
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public String getName() { return name; }
    public String getRegex() { return regex; }
    public String getType() { return type; }
}