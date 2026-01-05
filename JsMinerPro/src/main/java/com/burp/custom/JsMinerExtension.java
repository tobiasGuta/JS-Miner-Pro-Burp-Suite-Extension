package com.burp.custom;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.burp.custom.model.RegexRule;
import com.burp.custom.ui.ConfigTab;
import com.burp.custom.ui.ResultsTab;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class JsMinerExtension implements BurpExtension, HttpHandler {

    private MontoyaApi api;
    private ConfigTab configTab;
    private ResultsTab resultsTab;
    private List<Pattern> noisePatterns;

    // Hardcoded noise for efficiency
    private static final List<String> NOISE_DOMAINS = Arrays.asList(
            "www.w3.org", "schemas.openxmlformats.org", "schemas.microsoft.com",
            "purl.org", "openoffice.org", "docs.oasis-open.org",
            "example.com", "test.com", "localhost", "127.0.0.1",
            "npmjs.org", "github.com"
    );
    private static final List<String> MODULE_PREFIXES = Arrays.asList(
            "./", "../", ".../", "./lib", "../lib", "./utils", "../utils",
            "./node_modules", "./src", "./dist"
    );

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
        api.http().registerHttpHandler(this);

        // Initial load of noise patterns
        updateNoisePatterns();

        api.logging().logToOutput("JS Miner Pro Loaded successfully.");
    }

    private void updateNoisePatterns() {
        this.noisePatterns = Arrays.stream(configTab.getNoisePatterns())
                .filter(s -> !s.trim().isEmpty())
                .map(Pattern::compile)
                .collect(Collectors.toList());
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Refresh noise patterns on each request in case they were updated
        updateNoisePatterns();

        String url = responseReceived.initiatingRequest().url();

        // 1. Scope Check
        if (configTab.isScopeOnly() && !api.scope().isInScope(url)) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // 2. MIME Type Check
        String mime = responseReceived.inferredMimeType().name();
        boolean isMimeAllowed = Arrays.stream(configTab.getMimeTypes())
                .anyMatch(allowedMime -> mime.toLowerCase().contains(allowedMime.toLowerCase()));
        if (!isMimeAllowed) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // 3. Get body and check if empty
        String responseBody = responseReceived.bodyToString();
        if (responseBody.isEmpty()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        List<RegexRule> activeRules = configTab.getRules();

        for (RegexRule rule : activeRules) {
            if (!rule.isActive()) continue;

            try {
                Matcher matcher = rule.getPattern().matcher(responseBody);

                while (matcher.find()) {
                    String finding = (matcher.groupCount() > 0 && matcher.group(1) != null)
                            ? matcher.group(1)
                            : matcher.group(0);

                    // Noise Filtering Logic
                    if (isNoise(rule.getType(), finding)) {
                        continue;
                    }

                    api.logging().logToOutput("FOUND match (" + rule.getName() + "): " + finding);

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
                            matcher.start(),
                            matcher.end()
                    );
                }
            } catch (Exception e) {
                api.logging().logToError("Regex Error for rule '" + rule.getName() + "': " + e.getMessage());
            }
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private boolean isNoise(String type, String finding) {
        if (finding == null || finding.length() < 5) return true; // Basic length check

        // Check against user-defined regex noise patterns
        for (Pattern noise : noisePatterns) {
            if (noise.matcher(finding).find()) return true;
        }

        // Type-specific filtering
        if ("URL".equals(type) || "ENDPOINT".equals(type)) {
            for (String domain : NOISE_DOMAINS) {
                if (finding.contains(domain)) return true;
            }
        }

        if ("ENDPOINT".equals(type) || "FILE".equals(type)) {
            for (String prefix : MODULE_PREFIXES) {
                if (finding.startsWith(prefix)) return true;
            }
        }

        return false;
    }
}