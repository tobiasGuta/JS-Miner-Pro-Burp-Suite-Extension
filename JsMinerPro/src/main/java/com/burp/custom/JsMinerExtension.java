package com.burp.custom;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.burp.custom.model.RegexRule;
import com.burp.custom.ui.ConfigTab;
import com.burp.custom.ui.ResultsTab;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// CHANGED: Implements HttpHandler instead of ScanCheck.
// This forces Burp to show us traffic even if the Scanner is disabled or filtering JS.
public class JsMinerExtension implements BurpExtension, HttpHandler {

    private MontoyaApi api;
    private ConfigTab configTab;
    private ResultsTab resultsTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("JS Miner Pro");

        configTab = new ConfigTab(api);
        resultsTab = new ResultsTab(api);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Results", resultsTab);
        tabs.addTab("Configuration", configTab);

        api.userInterface().registerSuiteTab("JS Miner", tabs);

        // CHANGED: Register as HTTP Handler (sees all traffic)
        api.http().registerHttpHandler(this);

        api.logging().logToOutput("JS Miner Pro Loaded successfully (HttpHandler Mode).");
    }

    // Required by HttpHandler (we don't modify requests, so just continue)
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    // CHANGED: This replaces 'passiveAudit'. It runs on every response received.
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // 1. Get URL and Mime
        String url = responseReceived.initiatingRequest().url();
        String mime = responseReceived.inferredMimeType().name();
        short statusCode = responseReceived.statusCode();

        // 2. CHECK FOR 304 (Cached)
        if (statusCode == 304) {
            api.logging().logToOutput("SKIPPING [304]: " + url);
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // 3. DEBUG LOGGING (You should see this now!)
        api.logging().logToOutput("Scanning [" + statusCode + "]: " + url + " (" + mime + ")");

        // 4. Filter: Ignore images/css but ALLOW HTML/JS/JSON
        if (mime.contains("IMAGE") || mime.contains("CSS") || mime.contains("FONT") || url.endsWith(".css") || url.endsWith(".woff")) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        String responseBody = responseReceived.bodyToString();
        if (responseBody.isEmpty()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // 5. Iterate Rules
        List<RegexRule> activeRules = configTab.getRules();

        for (RegexRule rule : activeRules) {
            if (!rule.isActive()) continue;

            try {
                Pattern pattern = Pattern.compile(rule.getRegex());
                Matcher matcher = pattern.matcher(responseBody);

                while (matcher.find()) {
                    String finding = (matcher.groupCount() > 0) ? matcher.group(1) : matcher.group(0);
                    int start = matcher.start();
                    int end = matcher.end();

                    if (rule.getType().equals("PATH") && finding.length() < 3) continue;

                    api.logging().logToOutput("FOUND match: " + finding);

                    // Reconstruct HttpRequestResponse for the UI
                    HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(
                            responseReceived.initiatingRequest(),
                            responseReceived
                    );

                    resultsTab.addFinding(
                            rule.getType(),
                            finding,
                            rule.getName(),
                            url,
                            reqResp,
                            start,
                            end
                    );
                }
            } catch (Exception e) {
                api.logging().logToError("Regex Error: " + e.getMessage());
            }
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }
}