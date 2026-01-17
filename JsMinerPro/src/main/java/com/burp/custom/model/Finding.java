package com.burp.custom.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Objects;

public class Finding {
    private final String type;
    private final String finding;
    private final String ruleName;
    private final String url;
    // Removed 'transient' so Gson attempts to serialize it, but we need a custom adapter or a different strategy
    // because HttpRequestResponse is an interface and likely not directly serializable by Gson.
    // Instead, we will store the request/response as Strings for persistence.
    private final transient HttpRequestResponse requestResponse; 
    
    // New fields for persistence
    private String requestString;
    private String responseString;

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
        
        // Populate string versions for persistence
        if (requestResponse != null) {
            if (requestResponse.request() != null) {
                this.requestString = requestResponse.request().toString();
            }
            if (requestResponse.response() != null) {
                this.responseString = requestResponse.response().toString();
            }
        }
    }

    // Getters
    public String getType() { return type; }
    public String getFinding() { return finding; }
    public String getRuleName() { return ruleName; }
    public String getUrl() { return url; }
    public HttpRequestResponse getRequestResponse() { return requestResponse; }
    
    public String getRequestString() { return requestString; }
    public String getResponseString() { return responseString; }

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