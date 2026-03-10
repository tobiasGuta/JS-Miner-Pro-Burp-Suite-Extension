package com.burp.custom;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.burp.custom.model.RegexRule;
import com.burp.custom.ui.ConfigTab;
import com.burp.custom.ui.ResultsTab;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class JsMinerExtension implements BurpExtension, HttpHandler, ExtensionUnloadingHandler {

    private MontoyaApi api;
    private ConfigTab configTab;
    private ResultsTab resultsTab;
    private List<Pattern> noisePatterns;
    private ExecutorService executorService;
    private ScheduledExecutorService autoSaveScheduler;

    // Logging levels
    public enum LogLevel { DEBUG, INFO, WARN, ERROR }
    private LogLevel currentLogLevel = LogLevel.INFO;

    // Regex matching timeout in milliseconds
    private static final long REGEX_TIMEOUT_MS = 5000;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("JS Miner Pro");

        // Pass 'this' to ConfigTab so it can call updateNoisePatterns()
        configTab = new ConfigTab(api, this);
        resultsTab = new ResultsTab(api, this);

        // Initialize thread pool for background processing with bounded queue
        // Using LinkedBlockingQueue with capacity to prevent memory issues
        BlockingQueue<Runnable> workQueue = new LinkedBlockingQueue<>(1000);
        this.executorService = new ThreadPoolExecutor(
            2, 4, 60L, TimeUnit.SECONDS, workQueue,
            new ThreadPoolExecutor.DiscardOldestPolicy()
        );

        // Initialize auto-save scheduler (every 5 minutes)
        this.autoSaveScheduler = Executors.newSingleThreadScheduledExecutor();
        autoSaveScheduler.scheduleAtFixedRate(() -> {
            if (resultsTab != null) {
                resultsTab.saveAllFindings();
                log(LogLevel.DEBUG, "Auto-saved findings.");
            }
        }, 5, 5, TimeUnit.MINUTES);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Results", resultsTab);
        tabs.addTab("Configuration", configTab);

        api.userInterface().registerSuiteTab("JS Miner", tabs);
        api.http().registerHttpHandler(this);
        api.extension().registerUnloadingHandler(this);

        // Initial load of noise patterns
        updateNoisePatterns();

        log(LogLevel.INFO, "JS Miner Pro Loaded successfully.");
    }

    // Configurable logging
    public void setLogLevel(LogLevel level) {
        this.currentLogLevel = level;
    }

    public LogLevel getLogLevel() {
        return currentLogLevel;
    }

    public void log(LogLevel level, String message) {
        if (level.ordinal() >= currentLogLevel.ordinal()) {
            if (level == LogLevel.ERROR) {
                api.logging().logToError("[" + level + "] " + message);
            } else {
                api.logging().logToOutput("[" + level + "] " + message);
            }
        }
    }

    // Made public so ConfigTab can call it
    public void updateNoisePatterns() {
        List<Pattern> newPatterns = new ArrayList<>();
        for (String s : configTab.getNoisePatterns()) {
            if (s != null && !s.trim().isEmpty()) {
                try {
                    newPatterns.add(Pattern.compile(s.trim()));
                } catch (Exception e) {
                    log(LogLevel.WARN, "Invalid noise pattern skipped: " + s);
                }
            }
        }
        this.noisePatterns = newPatterns;
    }

    public List<String> getNoiseDomains() {
        return configTab.getNoiseDomains();
    }

    public List<String> getModulePrefixes() {
        return configTab.getModulePrefixes();
    }

    /**
     * Scans existing proxy history for JS files and other content.
     * This is called from the UI when user clicks "Scan Proxy History".
     */
    public void scanProxyHistory() {
        executorService.submit(() -> {
            log(LogLevel.INFO, "Starting proxy history scan...");
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            final int[] counters = {0, 0}; // [scanned, matched]
            
            for (ProxyHttpRequestResponse item : history) {
                try {
                    if (item.finalRequest() == null || item.response() == null) {
                        continue;
                    }
                    
                    String url = item.finalRequest().url();
                    HttpResponse response = item.response();
                    
                    // Check scope
                    if (configTab.isScopeOnly() && !api.scope().isInScope(url)) {
                        continue;
                    }
                    
                    // Check MIME type - more robust checking
                    if (!isMimeTypeAllowed(response, url)) {
                        continue;
                    }
                    
                    String responseBody = response.bodyToString();
                    if (responseBody == null || responseBody.isEmpty()) {
                        continue;
                    }
                    
                    // Check file size
                    double maxFileSizeMb = configTab.getMaxFileSizeMb();
                    long maxFileSizeBytes = (long) (maxFileSizeMb * 1_000_000);
                    if (responseBody.length() > maxFileSizeBytes) {
                        continue;
                    }
                    
                    counters[0]++; // scanned
                    
                    // Create HttpRequestResponse for findings
                    HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(
                        item.finalRequest(), response
                    );
                    
                    // Run regex rules
                    int findingsCount = analyzeContent(url, responseBody, reqResp);
                    if (findingsCount > 0) {
                        counters[1]++; // matched
                    }
                    
                } catch (Exception e) {
                    log(LogLevel.DEBUG, "Error processing history item: " + e.getMessage());
                }
            }
            
            final int finalScanned = counters[0];
            final int finalMatched = counters[1];
            log(LogLevel.INFO, "Proxy history scan complete. Scanned: " + finalScanned + " items, Found matches in: " + finalMatched + " items.");
            
            // Show completion message on EDT
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(resultsTab, 
                    "Scan complete!\n\nScanned: " + finalScanned + " items\nItems with matches: " + finalMatched,
                    "Proxy History Scan", JOptionPane.INFORMATION_MESSAGE);
            });
        });
    }

    /**
     * Checks if the MIME type is allowed for scanning.
     * More robust than just checking inferredMimeType.
     */
    private boolean isMimeTypeAllowed(HttpResponse response, String url) {
        String[] allowedMimes = configTab.getMimeTypes();
        
        // Method 1: Check Burp's inferred MIME type
        String inferredMime = response.inferredMimeType().name().toLowerCase();
        for (String allowed : allowedMimes) {
            if (inferredMime.contains(allowed.toLowerCase().trim())) {
                return true;
            }
        }
        
        // Method 2: Check Content-Type header
        String contentType = response.headerValue("Content-Type");
        if (contentType != null) {
            contentType = contentType.toLowerCase();
            for (String allowed : allowedMimes) {
                if (contentType.contains(allowed.toLowerCase().trim())) {
                    return true;
                }
            }
        }
        
        // Method 3: Check URL extension for common JS/JSON files
        String urlLower = url.toLowerCase();
        if (urlLower.endsWith(".js") || urlLower.endsWith(".mjs") || 
            urlLower.endsWith(".json") || urlLower.contains(".js?") ||
            urlLower.contains(".json?") || urlLower.contains("/api/")) {
            return true;
        }
        
        return false;
    }

    /**
     * Analyzes content and returns the number of findings.
     */
    private int analyzeContent(String url, String responseBody, HttpRequestResponse reqResp) {
        int findingsCount = 0;
        List<RegexRule> activeRules = configTab.getRules();

        for (RegexRule rule : activeRules) {
            if (!rule.isActive()) continue;
            
            Pattern pattern = rule.getPattern();
            if (pattern == null) {
                continue;
            }

            try {
                List<MatchResult> matches = findMatchesWithTimeout(pattern, responseBody, REGEX_TIMEOUT_MS);
                
                for (MatchResult match : matches) {
                    String finding = match.finding;

                    if (isNoise(rule.getType(), finding)) {
                        continue;
                    }

                    resultsTab.addFinding(
                            rule.getType(),
                            finding,
                            rule.getName(),
                            url,
                            reqResp,
                            match.start,
                            match.end,
                            rule.getSeverity()
                    );
                    findingsCount++;
                }
            } catch (TimeoutException e) {
                log(LogLevel.WARN, "Regex timeout for rule '" + rule.getName() + "' on URL: " + url);
            } catch (Exception e) {
                log(LogLevel.DEBUG, "Regex error: " + e.getMessage());
            }
        }
        
        return findingsCount;
    }

    @Override
    public void extensionUnloaded() {
        log(LogLevel.INFO, "JS Miner Pro unloading...");
        
        // Save findings automatically when the extension is unloaded
        if (resultsTab != null) {
            resultsTab.saveAllFindings();
            log(LogLevel.INFO, "Findings saved on unload.");
        }
        
        // Graceful shutdown of thread pool
        if (executorService != null) {
            executorService.shutdown();
            try {
                if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                    executorService.shutdownNow();
                    if (!executorService.awaitTermination(2, TimeUnit.SECONDS)) {
                        log(LogLevel.WARN, "Thread pool did not terminate cleanly.");
                    }
                }
            } catch (InterruptedException e) {
                executorService.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        // Shutdown auto-save scheduler
        if (autoSaveScheduler != null) {
            autoSaveScheduler.shutdown();
            try {
                if (!autoSaveScheduler.awaitTermination(2, TimeUnit.SECONDS)) {
                    autoSaveScheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                autoSaveScheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Offload analysis to a background thread to avoid blocking the UI/Proxy
        try {
            executorService.submit(() -> analyzeResponse(responseReceived));
        } catch (RejectedExecutionException e) {
            log(LogLevel.WARN, "Task queue full, skipping analysis for: " + responseReceived.initiatingRequest().url());
        }
        
        // Return immediately so Burp doesn't wait
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void analyzeResponse(HttpResponseReceived responseReceived) {
        String url = responseReceived.initiatingRequest().url();
        
        // 1. Scope Check
        if (configTab.isScopeOnly() && !api.scope().isInScope(url)) {
            return;
        }

        // 2. MIME Type Check - use the improved method
        if (!isMimeTypeAllowed(responseReceived, url)) {
            return;
        }

        // 3. Get body and check if empty
        String responseBody = responseReceived.bodyToString();
        if (responseBody == null || responseBody.isEmpty()) {
            return;
        }
        
        // Optimization: Limit body size analysis based on user config
        double maxFileSizeMb = configTab.getMaxFileSizeMb();
        long maxFileSizeBytes = (long) (maxFileSizeMb * 1_000_000);
        
        if (responseBody.length() > maxFileSizeBytes) {
            log(LogLevel.DEBUG, "Skipping large file: " + url);
            return;
        }

        log(LogLevel.DEBUG, "Analyzing: " + url);

        HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(
                responseReceived.initiatingRequest(),
                responseReceived
        );
        
        analyzeContent(url, responseBody, reqResp);
    }

    /**
     * Finds all matches with a timeout to prevent catastrophic backtracking
     */
    private List<MatchResult> findMatchesWithTimeout(Pattern pattern, String input, long timeoutMs) throws TimeoutException {
        List<MatchResult> results = new ArrayList<>();
        
        ExecutorService singleThread = Executors.newSingleThreadExecutor();
        Future<List<MatchResult>> future = singleThread.submit(() -> {
            List<MatchResult> matches = new ArrayList<>();
            Matcher matcher = pattern.matcher(input);
            while (matcher.find()) {
                if (Thread.currentThread().isInterrupted()) {
                    break;
                }
                String finding = (matcher.groupCount() > 0 && matcher.group(1) != null)
                        ? matcher.group(1)
                        : matcher.group(0);
                matches.add(new MatchResult(finding, matcher.start(), matcher.end()));
            }
            return matches;
        });

        try {
            results = future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (java.util.concurrent.TimeoutException e) {
            future.cancel(true);
            throw new TimeoutException("Regex matching timed out");
        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException("Regex matching failed", e);
        } finally {
            singleThread.shutdownNow();
        }
        
        return results;
    }

    private static class MatchResult {
        final String finding;
        final int start;
        final int end;

        MatchResult(String finding, int start, int end) {
            this.finding = finding;
            this.start = start;
            this.end = end;
        }
    }

    private boolean isNoise(String type, String finding) {
        if (finding == null || finding.length() < 5) return true; // Basic length check

        // Check against user-defined regex noise patterns
        if (noisePatterns != null) {
            for (Pattern noise : noisePatterns) {
                try {
                    if (noise.matcher(finding).find()) return true;
                } catch (Exception e) {
                    // Ignore invalid noise patterns
                }
            }
        }

        // Type-specific filtering using configurable domains
        if ("URL".equals(type) || "ENDPOINT".equals(type)) {
            for (String domain : getNoiseDomains()) {
                if (finding.contains(domain)) return true;
            }
        }

        if ("ENDPOINT".equals(type) || "FILE".equals(type)) {
            for (String prefix : getModulePrefixes()) {
                if (finding.startsWith(prefix)) return true;
            }
        }

        return false;
    }
}