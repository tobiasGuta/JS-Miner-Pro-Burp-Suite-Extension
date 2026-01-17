package com.burp.custom.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Objects;

public class Finding {
    private final String type;
    private final String finding;
    private final String ruleName;
    private final String url;
    private final transient HttpRequestResponse requestResponse; // Ignored by Gson for persistence
    private final int start;
    private final int end;

    public Finding(String type, String finding, String ruleName, String url, HttpRequestResponse requestResponse, int start, int end) {
        this.type = type;
        this.finding = finding;
        this.ruleName = ruleName;
        this.url = url;
        this.requestResponse = requestResponse;
        this.start = start;
        this.end = end;
    }

    // Getters
    public String getType() { return type; }
    public String getFinding() { return finding; }
    public String getRuleName() { return ruleName; }
    public String getUrl() { return url; }
    public HttpRequestResponse getRequestResponse() { return requestResponse; }
    public int getStart() { return start; }
    public int getEnd() { return end; }

    /**
     * Generates a unique key for deduplication purposes.
     * The key is a combination of the finding, its type, and the URL.
     */
    public String getUniqueKey() {
        return url + "::" + type + "::" + finding;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Finding finding1 = (Finding) o;
        return Objects.equals(getUniqueKey(), finding1.getUniqueKey());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getUniqueKey());
    }
}