package com.burp.custom;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.burp.custom.model.RegexRule;
import com.burp.custom.ui.ConfigTab;
import com.burp.custom.ui.ResultsTab;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class JsMinerExtension implements BurpExtension, HttpHandler, ExtensionUnloadingHandler {

    private MontoyaApi api;
    private ConfigTab configTab;
    private ResultsTab resultsTab;
    private List<Pattern> noisePatterns;
    private ExecutorService executorService;

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

        // Pass 'this' to ConfigTab so it can call updateNoisePatterns()
        configTab = new ConfigTab(api, this);
        resultsTab = new ResultsTab(api);

        // Initialize thread pool for background processing
        // Reduced to 2 threads to minimize CPU contention
        this.executorService = Executors.newFixedThreadPool(2); 

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Results", resultsTab);
        tabs.addTab("Configuration", configTab);

        api.userInterface().registerSuiteTab("JS Miner", tabs);
        api.http().registerHttpHandler(this);
        api.extension().registerUnloadingHandler(this);

        // Initial load of noise patterns
        updateNoisePatterns();

        api.logging().logToOutput("JS Miner Pro Loaded successfully.");
    }

    // Made public so ConfigTab can call it
    public void updateNoisePatterns() {
        this.noisePatterns = Arrays.stream(configTab.getNoisePatterns())
                .filter(s -> !s.trim().isEmpty())
                .map(Pattern::compile)
                .collect(Collectors.toList());
    }

    @Override
    public void extensionUnloaded() {
        // Save findings automatically when the extension is unloaded (e.g., Burp closing)
        if (resultsTab != null) {
            resultsTab.saveAllFindings();
            api.logging().logToOutput("JS Miner Pro: Findings saved on unload.");
        }
        
        // Shutdown thread pool
        if (executorService != null) {
            executorService.shutdownNow();
        }
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Offload analysis to a background thread to avoid blocking the UI/Proxy
        executorService.submit(() -> analyzeResponse(responseReceived));
        
        // Return immediately so Burp doesn't wait
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void analyzeResponse(HttpResponseReceived responseReceived) {
        String url = responseReceived.initiatingRequest().url();
        
        // 1. Scope Check
        if (configTab.isScopeOnly() && !api.scope().isInScope(url)) {
            return;
        }

        // 2. MIME Type Check
        String[] allowedMimes = configTab.getMimeTypes();
        String mime = responseReceived.inferredMimeType().name();
        boolean isMimeAllowed = Arrays.stream(allowedMimes)
                .anyMatch(allowedMime -> mime.toLowerCase().contains(allowedMime.toLowerCase().trim()));
        
        if (!isMimeAllowed) {
            return;
        }

        // 3. Get body and check if empty
        String responseBody = responseReceived.bodyToString();
        if (responseBody.isEmpty()) {
            return;
        }
        
        // Optimization: Limit body size analysis based on user config
        double maxFileSizeMb = configTab.getMaxFileSizeMb();
        long maxFileSizeBytes = (long) (maxFileSizeMb * 1_000_000);
        
        if (responseBody.length() > maxFileSizeBytes) {
             // api.logging().logToOutput("SKIPPING Large File: " + url); // Commented out to reduce log spam
             return;
        }

        // api.logging().logToOutput("ANALYZING (Background): " + url); // Commented out to reduce log spam

        List<RegexRule> activeRules = configTab.getRules();

        for (RegexRule rule : activeRules) {
            if (!rule.isActive()) continue;

            try {
                // IMPORTANT: Use a timeout or interruptible matcher if possible, but Java regex doesn't support timeouts natively easily.
                // Instead, we rely on the simplified regexes in ConfigTab.
                
                Matcher matcher = rule.getPattern().matcher(responseBody);

                while (matcher.find()) {
                    String finding = (matcher.groupCount() > 0 && matcher.group(1) != null)
                            ? matcher.group(1)
                            : matcher.group(0);

                    // Noise Filtering Logic
                    if (isNoise(rule.getType(), finding)) {
                        continue;
                    }

                    // api.logging().logToOutput("FOUND match (" + rule.getName() + "): " + finding); // Reduced log spam

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
    }

    private boolean isNoise(String type, String finding) {
        if (finding == null || finding.length() < 5) return true; // Basic length check

        // Check against user-defined regex noise patterns
        if (noisePatterns != null) {
            for (Pattern noise : noisePatterns) {
                if (noise.matcher(finding).find()) return true;
            }
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