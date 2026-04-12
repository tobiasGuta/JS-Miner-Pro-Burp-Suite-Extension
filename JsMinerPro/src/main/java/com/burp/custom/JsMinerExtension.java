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
import com.burp.custom.ui.StatsTab;
import com.burp.custom.util.EntropyAnalyzer;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JsMinerExtension implements BurpExtension, HttpHandler, ExtensionUnloadingHandler {

    private MontoyaApi api;
    private ConfigTab configTab;
    private ResultsTab resultsTab;
    private StatsTab statsTab;

    // Thread-safe noise pattern storage — replaced atomically on config save
    private final AtomicReference<List<Pattern>> noisePatterns = new AtomicReference<>(Collections.emptyList());

    // Main analysis thread pool (background scanning)
    private ExecutorService executorService;

    // SHARED timeout pool for regex matching — reused across all rule evaluations.
    // Fixes the critical bug of creating a new ExecutorService per regex match.
    private ExecutorService regexTimeoutPool;

    private ScheduledExecutorService autoSaveScheduler;

    private static final long REGEX_TIMEOUT_MS = 3000;
    public static final int CONTEXT_WINDOW = 100;

    public enum LogLevel { DEBUG, INFO, WARN, ERROR }
    private volatile LogLevel currentLogLevel = LogLevel.INFO;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("JS Miner Pro");

        configTab = new ConfigTab(api, this);
        resultsTab = new ResultsTab(api, this);
        statsTab   = new StatsTab(api);

        BlockingQueue<Runnable> workQueue = new LinkedBlockingQueue<>(1000);
        this.executorService = new ThreadPoolExecutor(
            2, 4, 60L, TimeUnit.SECONDS, workQueue,
            new ThreadPoolExecutor.DiscardOldestPolicy()
        );

        // Shared pool — eliminates per-match executor creation overhead
        this.regexTimeoutPool = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "jsminer-regex-worker");
            t.setDaemon(true);
            return t;
        });

        this.autoSaveScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "jsminer-autosave");
            t.setDaemon(true);
            return t;
        });
        autoSaveScheduler.scheduleAtFixedRate(() -> {
            if (resultsTab != null) resultsTab.saveAllFindings();
        }, 5, 5, TimeUnit.MINUTES);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Results",       resultsTab);
        tabs.addTab("Stats",         statsTab);
        tabs.addTab("Configuration", configTab);

        api.userInterface().registerSuiteTab("JS Miner Pro", tabs);
        api.http().registerHttpHandler(this);
        api.extension().registerUnloadingHandler(this);

        updateNoisePatterns();
        log(LogLevel.INFO, "JS Miner Pro loaded successfully.");
    }

    public void setLogLevel(LogLevel level) { this.currentLogLevel = level; }
    public LogLevel getLogLevel()           { return currentLogLevel; }

    public void log(LogLevel level, String message) {
        if (level.ordinal() >= currentLogLevel.ordinal()) {
            if (level == LogLevel.ERROR) {
                api.logging().logToError("[" + level + "] " + message);
            } else {
                api.logging().logToOutput("[" + level + "] " + message);
            }
        }
    }

    // Atomically replaces the noise pattern list — background threads always
    // see either the old complete list or the new one, never a partial build.
    public void updateNoisePatterns() {
        List<Pattern> built = new ArrayList<>();
        for (String s : configTab.getNoisePatterns()) {
            if (s != null && !s.trim().isEmpty()) {
                try {
                    built.add(Pattern.compile(s.trim()));
                } catch (Exception e) {
                    log(LogLevel.WARN, "Invalid noise pattern skipped: " + s);
                }
            }
        }
        noisePatterns.set(Collections.unmodifiableList(built));
    }

    public List<String> getNoiseDomains()   { return configTab.getNoiseDomains(); }
    public List<String> getModulePrefixes() { return configTab.getModulePrefixes(); }

    // Single shared gate used by both live handler and proxy history scanner
    private boolean shouldAnalyze(String url, HttpResponse response) {
        if (configTab.isScopeOnly() && !api.scope().isInScope(url)) return false;
        if (!isMimeTypeAllowed(response, url)) return false;
        // Use byte length (not char length) to avoid chars-vs-bytes mismatch bug
        long maxBytes = (long) (configTab.getMaxFileSizeMb() * 1_000_000);
        if (response.body().length() > maxBytes) {
            log(LogLevel.DEBUG, "Skipping oversized file (" + response.body().length() + " bytes): " + url);
            return false;
        }
        return true;
    }

    public void scanProxyHistory() {
        executorService.submit(() -> {
            log(LogLevel.INFO, "Starting proxy history scan...");
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int scanned = 0, matched = 0;

            for (ProxyHttpRequestResponse item : history) {
                try {
                    if (item.finalRequest() == null || item.response() == null) continue;
                    String url = item.finalRequest().url();
                    HttpResponse response = item.response();
                    if (!shouldAnalyze(url, response)) continue;
                    String body = response.bodyToString();
                    if (body == null || body.isEmpty()) continue;
                    scanned++;
                    HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(item.finalRequest(), response);
                    if (analyzeContent(url, body, reqResp) > 0) matched++;
                } catch (Exception e) {
                    log(LogLevel.DEBUG, "Error processing history item: " + e.getMessage());
                }
            }

            final int fs = scanned, fm = matched;
            log(LogLevel.INFO, "Scan complete. Scanned: " + fs + ", Matched: " + fm);
            SwingUtilities.invokeLater(() ->
                JOptionPane.showMessageDialog(resultsTab,
                    "Scan complete!\n\nScanned: " + fs + " items\nItems with matches: " + fm,
                    "Proxy History Scan", JOptionPane.INFORMATION_MESSAGE)
            );
        });
    }

    private boolean isMimeTypeAllowed(HttpResponse response, String url) {
        String[] allowedMimes = configTab.getMimeTypes();

        String inferredMime = response.inferredMimeType().name().toLowerCase();
        for (String allowed : allowedMimes) {
            if (inferredMime.contains(allowed.toLowerCase().trim())) return true;
        }

        String contentType = response.headerValue("Content-Type");
        if (contentType != null) {
            contentType = contentType.toLowerCase();
            for (String allowed : allowedMimes) {
                if (contentType.contains(allowed.toLowerCase().trim())) return true;
            }
        }

        // Extension-only fallback — removed the overbroad "/api/" catch-all
        // that previously allowed binary responses to pass through
        String urlLower = url.toLowerCase().split("\\?")[0];
        return urlLower.endsWith(".js")   || urlLower.endsWith(".mjs")  ||
               urlLower.endsWith(".jsx")  || urlLower.endsWith(".ts")   ||
               urlLower.endsWith(".tsx")  || urlLower.endsWith(".json") ||
               urlLower.endsWith(".map");
    }

    int analyzeContent(String url, String responseBody, HttpRequestResponse reqResp) {
        int count = 0;
        // getRules() returns a defensive copy — safe to iterate on background thread
        List<RegexRule> rules = configTab.getRules();

        for (RegexRule rule : rules) {
            if (!rule.isActive()) continue;
            Pattern pattern = rule.getPattern();
            if (pattern == null) continue;

            try {
                List<MatchResult> matches = findMatchesWithTimeout(pattern, responseBody, REGEX_TIMEOUT_MS);
                for (MatchResult match : matches) {
                    String finding = match.finding;
                    if (isNoise(rule.getType(), finding)) continue;

                    // Entropy-assisted severity correction
                    String effectiveSeverity = adjustSeverityByEntropy(rule.getSeverity(), rule.getType(), finding);

                    // Context window around the match
                    String context = extractContext(responseBody, match.start, match.end);

                    resultsTab.addFinding(rule.getType(), finding, rule.getName(),
                        url, reqResp, match.start, match.end, effectiveSeverity, context);
                    statsTab.recordFinding(url, rule.getType(), effectiveSeverity);
                    count++;
                }
            } catch (TimeoutException e) {
                log(LogLevel.WARN, "Regex timeout for rule '" + rule.getName() + "' on: " + url);
            } catch (Exception e) {
                log(LogLevel.DEBUG, "Regex error for rule '" + rule.getName() + "': " + e.getMessage());
            }
        }
        return count;
    }

    private String adjustSeverityByEntropy(String declared, String type, String finding) {
        if (!"SECRET".equals(type) || finding.length() < 16) return declared;
        double entropy = EntropyAnalyzer.calculateEntropy(finding);
        // Very low entropy → almost certainly a placeholder/variable name
        if (entropy < 2.5 && ("HIGH".equals(declared) || "MEDIUM".equals(declared))) {
            log(LogLevel.DEBUG, "Downgrading low-entropy SECRET to INFO: '" + finding + "' (entropy=" + String.format("%.2f", entropy) + ")");
            return "INFO";
        }
        // Moderate entropy → downgrade HIGH to MEDIUM as caution flag
        if (entropy < 3.5 && "HIGH".equals(declared)) return "MEDIUM";
        // Very high entropy on a weak-typed rule → upgrade
        if (entropy >= 5.0 && ("INFO".equals(declared) || "LOW".equals(declared))) return "MEDIUM";
        return declared;
    }

    private String extractContext(String body, int start, int end) {
        int ctxStart = Math.max(0, start - CONTEXT_WINDOW);
        int ctxEnd   = Math.min(body.length(), end + CONTEXT_WINDOW);
        return body.substring(ctxStart, ctxEnd).replaceAll("[\\s]+", " ").trim();
    }

    // Uses the SHARED regexTimeoutPool — no new pool created per call
    private List<MatchResult> findMatchesWithTimeout(Pattern pattern, String input, long timeoutMs)
            throws TimeoutException {
        Future<List<MatchResult>> future = regexTimeoutPool.submit(() -> {
            List<MatchResult> matches = new ArrayList<>();
            Matcher matcher = pattern.matcher(input);
            while (matcher.find()) {
                if (Thread.currentThread().isInterrupted()) break;
                String finding = (matcher.groupCount() > 0 && matcher.group(1) != null)
                    ? matcher.group(1) : matcher.group(0);
                matches.add(new MatchResult(finding, matcher.start(), matcher.end()));
            }
            return matches;
        });
        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (java.util.concurrent.TimeoutException e) {
            future.cancel(true);
            throw new TimeoutException("Regex matching timed out");
        } catch (InterruptedException | ExecutionException e) {
            future.cancel(true);
            throw new RuntimeException("Regex matching failed", e);
        }
    }

    static class MatchResult {
        final String finding;
        final int start, end;
        MatchResult(String finding, int start, int end) {
            this.finding = finding; this.start = start; this.end = end;
        }
    }

    private boolean isNoise(String type, String finding) {
        if (finding == null || finding.length() < 5) return true;
        // Atomic read — always a complete, immutable snapshot
        for (Pattern noise : noisePatterns.get()) {
            try { if (noise.matcher(finding).find()) return true; }
            catch (Exception ignored) { }
        }
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

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            executorService.submit(() -> analyzeResponse(responseReceived));
        } catch (RejectedExecutionException e) {
            log(LogLevel.WARN, "Task queue full, skipping: " + responseReceived.initiatingRequest().url());
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void analyzeResponse(HttpResponseReceived responseReceived) {
        String url = responseReceived.initiatingRequest().url();
        if (!shouldAnalyze(url, responseReceived)) return;
        String body = responseReceived.bodyToString();
        if (body == null || body.isEmpty()) return;
        log(LogLevel.DEBUG, "Analyzing: " + url);
        HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(
            responseReceived.initiatingRequest(), responseReceived);
        analyzeContent(url, body, reqResp);
    }

    @Override
    public void extensionUnloaded() {
        log(LogLevel.INFO, "JS Miner Pro unloading...");
        if (resultsTab != null) {
            resultsTab.saveAllFindings();
            log(LogLevel.INFO, "Findings saved on unload.");
        }
        shutdownPool(executorService,   "analysis pool");
        shutdownPool(regexTimeoutPool,  "regex timeout pool");
        shutdownPool(autoSaveScheduler, "auto-save scheduler");
    }

    private void shutdownPool(ExecutorService pool, String name) {
        if (pool == null) return;
        pool.shutdown();
        try {
            if (!pool.awaitTermination(5, TimeUnit.SECONDS)) {
                pool.shutdownNow();
                if (!pool.awaitTermination(2, TimeUnit.SECONDS))
                    log(LogLevel.WARN, name + " did not terminate cleanly.");
            }
        } catch (InterruptedException e) {
            pool.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
