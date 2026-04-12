package com.burp.custom.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import java.util.Objects;

public class Finding {
    private final String type;
    private final String finding;
    private final String ruleName;
    private final String url;
    private final String severity;
    private final transient HttpRequestResponse requestResponse;
    private String requestString;
    private String responseString;
    private final int start;
    private final int end;
    private final long timestamp;
    // Context window — surrounding text extracted at analysis time
    private final String context;

    public Finding(String type, String finding, String ruleName, String url,
                   HttpRequestResponse requestResponse, int start, int end) {
        this(type, finding, ruleName, url, requestResponse, start, end, "INFO", "");
    }

    public Finding(String type, String finding, String ruleName, String url,
                   HttpRequestResponse requestResponse, int start, int end, String severity) {
        this(type, finding, ruleName, url, requestResponse, start, end, severity, "");
    }

    public Finding(String type, String finding, String ruleName, String url,
                   HttpRequestResponse requestResponse, int start, int end,
                   String severity, String context) {
        this.type            = type;
        this.finding         = finding;
        this.ruleName        = ruleName;
        this.url             = url;
        this.requestResponse = requestResponse;
        this.start           = start;
        this.end             = end;
        this.severity        = severity != null ? severity : "INFO";
        this.context         = context != null ? context : "";
        this.timestamp       = System.currentTimeMillis();

        if (requestResponse != null) {
            if (requestResponse.request()  != null) this.requestString  = requestResponse.request().toString();
            if (requestResponse.response() != null) this.responseString = requestResponse.response().toString();
        }
    }

    public String getType()             { return type; }
    public String getFinding()          { return finding; }
    public String getRuleName()         { return ruleName; }
    public String getUrl()              { return url; }
    public String getSeverity()         { return severity != null ? severity : "INFO"; }
    public String getContext()          { return context != null ? context : ""; }
    public HttpRequestResponse getRequestResponse() { return requestResponse; }
    public String getRequestString()    { return requestString; }
    public String getResponseString()   { return responseString; }
    public int getStart()               { return start; }
    public int getEnd()                 { return end; }
    public long getTimestamp()          { return timestamp; }

    public int getSeverityOrder() {
        switch (getSeverity().toUpperCase()) {
            case "HIGH":   return 4;
            case "MEDIUM": return 3;
            case "LOW":    return 2;
            case "INFO":   return 1;
            default:       return 0;
        }
    }

    public String getUniqueKey() {
        // Dedup key includes finding value + type only (not URL), so the same
        // secret found across multiple files is treated as a single unique secret
        // and the URL-reuse counter accurately reflects cross-file exposure.
        return type + "::" + finding;
    }

    // URL-scoped key used when we want to track the specific URL of discovery
    public String getUrlScopedKey() {
        return url + "::" + type + "::" + finding;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return Objects.equals(getUniqueKey(), ((Finding) o).getUniqueKey());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getUniqueKey());
    }
}
