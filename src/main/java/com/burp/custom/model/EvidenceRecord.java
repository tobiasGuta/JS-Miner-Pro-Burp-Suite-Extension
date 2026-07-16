package com.burp.custom.model;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** One shared HTTP evidence object for all findings from the same response. */
public class EvidenceRecord {
    private static final int MAX_REQUEST_CHARS = 16_384;
    private static final int MAX_RESPONSE_CHARS = 49_152;
    private final String id;
    private final String url;
    private final String responseHash;
    private final String requestString;
    private final String responseString;
    private transient HttpRequestResponse requestResponse;

    public EvidenceRecord(String url, HttpRequestResponse requestResponse) {
        this(url, requestResponse, null);
    }

    public EvidenceRecord(String url, HttpRequestResponse requestResponse, String knownResponseHash) {
        this.url = url;
        this.requestResponse = null;
        this.requestString = requestResponse != null && requestResponse.request() != null
            ? copyIfAtMost(requestResponse.request().toString(), MAX_REQUEST_CHARS) : null;
        String rawResponse = requestResponse != null && requestResponse.response() != null
            ? requestResponse.response().toString() : "";
        this.responseString = copyIfAtMost(rawResponse, MAX_RESPONSE_CHARS);
        this.responseHash = knownResponseHash != null ? knownResponseHash : sha256(rawResponse);
        this.id = responseHash;
    }

    public EvidenceRecord(String id, String url, String responseHash, String requestString, String responseString) {
        this.id = id;
        this.url = url;
        this.responseHash = responseHash;
        this.requestString = requestString;
        this.responseString = responseString;
    }

    public String getId() { return id; }
    public String getUrl() { return url; }
    public String getResponseHash() { return responseHash; }
    public HttpRequestResponse getRequestResponse() { return requestResponse; }
    public String getRequestString() { return requestString; }
    public String getResponseString() { return responseString; }

    public HttpRequest getRequest() {
        if (requestResponse != null) return requestResponse.request();
        return requestString == null ? null : HttpRequest.httpRequest(requestString);
    }

    public HttpResponse getResponse() {
        if (requestResponse != null) return requestResponse.response();
        return responseString == null ? null : HttpResponse.httpResponse(responseString);
    }

    public EvidenceRecord forPersistence(boolean includeRawHttp) {
        return new EvidenceRecord(id, url, responseHash,
            includeRawHttp ? requestString : null, includeRawHttp ? responseString : null);
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    public static String responseHash(String response) {
        return sha256(response == null ? "" : response);
    }

    private static String copyIfAtMost(String value, int maxChars) {
        return value != null && value.length() <= maxChars ? value : null;
    }
}
