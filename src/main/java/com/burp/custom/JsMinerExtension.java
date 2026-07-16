package com.burp.custom;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.burp.custom.model.RegexRule;
import com.burp.custom.model.EvidenceRecord;
import com.burp.custom.model.EntropyPolicy;
import com.burp.custom.ui.ConfigTab;
import com.burp.custom.ui.ResultsTab;
import com.burp.custom.ui.StatsTab;
import com.burp.custom.util.EntropyAnalyzer;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public class JsMinerExtension implements BurpExtension, HttpHandler, ExtensionUnloadingHandler {

    private MontoyaApi api;
    private ConfigTab configTab;
    private ResultsTab resultsTab;
    private StatsTab statsTab;

    // Thread-safe noise pattern storage — replaced atomically on config save
    private final AtomicReference<ScannerConfig> activeConfig =
        new AtomicReference<>(new ScannerConfig(true, 2_000_000L, List.of(), "", List.of(), List.of(), List.of(), List.of()));

    // Main analysis thread pool (background scanning)
    private ExecutorService executorService;

    private ScheduledExecutorService autoSaveScheduler;
    private volatile boolean clearFindingsOnProjectClose;
    private final AtomicLong droppedResponses = new AtomicLong();
    private final AtomicLong lastDropWarningMillis = new AtomicLong();
    private final AtomicBoolean historyScanRunning = new AtomicBoolean();
    private final AtomicBoolean acceptingResponses = new AtomicBoolean(true);
    private final Map<String, Boolean> responseDedupCache = Collections.synchronizedMap(
        new LinkedHashMap<>(256, 0.75f, true) {
            @Override protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) { return size() > 1_024; }
        });

    public static final int CONTEXT_WINDOW = 100;
    private static final int MAX_MATCHES_PER_RULE = 100;
    private static final int MAX_FINDINGS_PER_RESPONSE = 500;

    public enum LogLevel { DEBUG, INFO, WARN, ERROR }
    private volatile LogLevel currentLogLevel = LogLevel.INFO;

    record CompiledRule(String name, String type, String severity, EntropyPolicy entropyPolicy, Pattern pattern) { }

    record ScannerConfig(boolean scopeOnly, long maxBytes, List<String> mimeTypes, String rulesetVersion,
                         List<Pattern> noisePatterns, List<String> noiseDomains,
                         List<String> modulePrefixes, List<CompiledRule> rules) { }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("JS Miner Pro");

        configTab = new ConfigTab(api, this);
        resultsTab = new ResultsTab(api, this);
        statsTab   = new StatsTab(api);
        resultsTab.setStatsTab(statsTab);

        BlockingQueue<Runnable> workQueue = new LinkedBlockingQueue<>(1000);
        this.executorService = new ThreadPoolExecutor(
            2, 4, 60L, TimeUnit.SECONDS, workQueue,
            (task, executor) -> {
                if (!executor.isShutdown()) recordDroppedResponse();
                throw new RejectedExecutionException("Analysis queue full");
            }
        );

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

        configTab.applyScannerConfig();
        log(LogLevel.INFO, "JS Miner Pro loaded successfully.");
    }

    public void setLogLevel(LogLevel level) { this.currentLogLevel = level; }
    public LogLevel getLogLevel()           { return currentLogLevel; }

    public void updateFindingRetentionOptions(int globalLimit, int perHostLimit,
                                              boolean persistRawHttp, boolean clearOnProjectClose) {
        this.clearFindingsOnProjectClose = clearOnProjectClose;
        if (resultsTab != null) resultsTab.setRetentionOptions(globalLimit, perHostLimit, persistRawHttp);
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

    // Atomically replaces the noise pattern list — background threads always
    // see either the old complete list or the new one, never a partial build.
    public void updateScannerConfig(boolean scopeOnly, double maxFileSizeMb, String[] mimeTypes,
                                    String[] noisePatternStrings, List<String> noiseDomains,
                                    List<String> modulePrefixes, List<RegexRule> rules) {
        List<Pattern> noisePatterns = new ArrayList<>();
        for (String value : noisePatternStrings) {
            if (value == null || value.trim().isEmpty()) continue;
            try {
                noisePatterns.add(Pattern.compile(value.trim()));
            } catch (Exception e) {
                log(LogLevel.WARN, "Invalid noise pattern skipped: " + value);
            }
        }

        List<CompiledRule> compiledRules = new ArrayList<>();
        for (RegexRule rule : rules) {
            if (!rule.isActive()) continue;
            Pattern pattern = rule.getPattern();
            if (pattern == null) {
                log(LogLevel.WARN, "Invalid rule skipped: " + rule.getName() + " (" + rule.getPatternError() + ")");
                continue;
            }
            compiledRules.add(new CompiledRule(rule.getName(), rule.getType(), rule.getSeverity(), rule.getEntropyPolicy(), pattern));
        }

        long maxBytes = Double.isFinite(maxFileSizeMb) && maxFileSizeMb >= 0
            ? (long) (maxFileSizeMb * 1_000_000) : 2_000_000L;
        String rulesetVersion = Integer.toHexString(compiledRules.hashCode());
        activeConfig.set(new ScannerConfig(scopeOnly, maxBytes, normalize(mimeTypes), rulesetVersion, List.copyOf(noisePatterns),
            List.copyOf(noiseDomains), List.copyOf(modulePrefixes), List.copyOf(compiledRules)));
    }

    private void recordDroppedResponse() {
        long dropped = droppedResponses.incrementAndGet();
        long now = System.currentTimeMillis();
        long previous = lastDropWarningMillis.get();
        if (now - previous >= 30_000 && lastDropWarningMillis.compareAndSet(previous, now)) {
            log(LogLevel.WARN, "Analysis queue full; dropped " + dropped + " response task(s) so far.");
        }
    }

    private List<String> normalize(String[] values) {
        List<String> normalized = new ArrayList<>();
        for (String value : values) {
            if (value != null && !value.trim().isEmpty()) normalized.add(value.trim().toLowerCase());
        }
        return List.copyOf(normalized);
    }


    // Single shared gate used by both live handler and proxy history scanner
    private boolean shouldAnalyze(String url, HttpResponse response, ScannerConfig config) {
        if (config.scopeOnly() && !api.scope().isInScope(url)) return false;
        if (!isMimeTypeAllowed(response, url, config)) return false;
        // Use byte length (not char length) to avoid chars-vs-bytes mismatch bug
        if (response.body().length() > config.maxBytes()) {
            log(LogLevel.DEBUG, "Skipping oversized file (" + response.body().length() + " bytes): " + url);
            return false;
        }
        return true;
    }

    public void scanProxyHistory() {
        scanProxyHistory(() -> { });
    }

    public void scanProxyHistory(Runnable completion) {
        if (!historyScanRunning.compareAndSet(false, true)) {
            log(LogLevel.WARN, "Proxy history scan already running.");
            SwingUtilities.invokeLater(completion);
            return;
        }
        try {
            executorService.submit(() -> {
            try {
            log(LogLevel.INFO, "Starting proxy history scan...");
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int scanned = 0, matched = 0;

            for (ProxyHttpRequestResponse item : history) {
                try {
                    if (item.finalRequest() == null || item.response() == null) continue;
                    String url = item.finalRequest().url();
                    HttpResponse response = item.response();
                    ScannerConfig config = activeConfig.get();
                    if (!shouldAnalyze(url, response, config)) continue;
                    String body = response.bodyToString();
                    if (body == null || body.isEmpty()) continue;
                    if (!isMostlyPrintable(body)) continue;
                    if (!shouldScanResponse(url, body, config)) continue;
                    scanned++;
                    HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(item.finalRequest(), response);
                    if (analyzeContent(url, body, reqResp, config) > 0) matched++;
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
            } finally {
                historyScanRunning.set(false);
                SwingUtilities.invokeLater(completion);
            }
        });
        } catch (RejectedExecutionException e) {
            historyScanRunning.set(false);
            SwingUtilities.invokeLater(completion);
        }
    }

    private boolean isMimeTypeAllowed(HttpResponse response, String url, ScannerConfig config) {
        List<String> allowedMimes = config.mimeTypes();

        String inferredMime = response.inferredMimeType().name().toLowerCase();
        for (String allowed : allowedMimes) {
            if (inferredMime.contains(allowed)) return true;
        }

        String contentType = response.headerValue("Content-Type");
        if (contentType != null) {
            contentType = contentType.toLowerCase();
            for (String allowed : allowedMimes) {
                if (contentType.contains(allowed)) return true;
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

    private boolean isMostlyPrintable(String body) {
        if (body.isEmpty()) return false;
        int printable = 0;
        int checked = Math.min(body.length(), 8_192);
        for (int i = 0; i < checked; i++) {
            char c = body.charAt(i);
            if (Character.isWhitespace(c) || (c >= 0x20 && c != 0x7f)) printable++;
        }
        return printable >= checked * 0.85;
    }

    private boolean shouldScanResponse(String url, String body, ScannerConfig config) {
        String canonicalUrl = canonicalUrl(url);
        String key = canonicalUrl + "\n" + EvidenceRecord.responseHash(body) + "\n" + config.rulesetVersion();
        synchronized (responseDedupCache) {
            if (responseDedupCache.containsKey(key)) return false;
            responseDedupCache.put(key, Boolean.TRUE);
            return true;
        }
    }

    private String canonicalUrl(String url) {
        return url.split("\\?", 2)[0];
    }

    int analyzeContent(String url, String responseBody, HttpRequestResponse reqResp, ScannerConfig config) {
        int count = 0;
        String responseHash = EvidenceRecord.responseHash(responseBody);
        String requestMethod = reqResp.request() != null ? reqResp.request().method() : "";
        String requestBody = reqResp.request() != null ? reqResp.request().bodyToString() : "";
        String evidenceId = EvidenceRecord.evidenceId(requestMethod, canonicalUrl(url), requestBody, responseHash);
        List<ResultsTab.FindingCandidate> candidates = new ArrayList<>();
        // getRules() returns a defensive copy — safe to iterate on background thread
        for (CompiledRule rule : config.rules()) {

            try {
                List<MatchResult> matches = findMatches(rule.pattern(), responseBody, MAX_MATCHES_PER_RULE);
                for (MatchResult match : matches) {
                    String finding = match.finding;
                    if (isNoise(config, rule.type(), finding)) continue;

                    // Entropy-assisted severity correction
                    String effectiveSeverity = applyEntropyPolicy(rule.severity(), rule.type(), rule.entropyPolicy(), finding);
                    if (effectiveSeverity == null) continue;

                    // Context window around the match
                    String context = extractContext(responseBody, match.start, match.end);

                    candidates.add(new ResultsTab.FindingCandidate(rule.type(), finding, rule.name(), url, evidenceId, responseHash,
                        reqResp, match.start, match.end, effectiveSeverity, context));
                    count++;
                    if (count >= MAX_FINDINGS_PER_RESPONSE) {
                        log(LogLevel.WARN, "Finding cap reached on: " + url);
                        resultsTab.addFindingsBatch(candidates);
                        return count;
                    }
                }
            } catch (Exception e) {
                log(LogLevel.DEBUG, "Regex error for rule '" + rule.name() + "': " + e.getMessage());
            }
        }
        resultsTab.addFindingsBatch(candidates);
        return count;
    }

    private String applyEntropyPolicy(String declared, String type, EntropyPolicy policy, String finding) {
        if (policy == EntropyPolicy.NONE || !"SECRET".equals(type) || finding.length() < 16) return declared;
        double entropy = EntropyAnalyzer.calculateEntropy(finding);
        if (policy == EntropyPolicy.REQUIRE_MINIMUM) return entropy >= 3.0 ? declared : null;
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

    private List<MatchResult> findMatches(Pattern pattern, String input, int maxMatches) {
        List<MatchResult> matches = new ArrayList<>();
        Matcher matcher = pattern.matcher(input);
        while (matcher.find()) {
            int groupIndex = extractPreferredGroupIndex(matcher);
            String finding = matcher.group(groupIndex);
            matches.add(new MatchResult(finding, matcher.start(groupIndex), matcher.end(groupIndex)));
            if (matches.size() >= maxMatches) break;
        }
        return matches;
    }

    private int extractPreferredGroupIndex(Matcher matcher) {
        for (int groupIndex = 1; groupIndex <= matcher.groupCount(); groupIndex++) {
            if (matcher.group(groupIndex) != null) return groupIndex;
        }
        return 0;
    }

    static class MatchResult {
        final String finding;
        final int start, end;
        MatchResult(String finding, int start, int end) {
            this.finding = finding; this.start = start; this.end = end;
        }
    }

    private boolean isNoise(ScannerConfig config, String type, String finding) {
        if (finding == null || finding.length() < 5) return true;
        // Atomic read — always a complete, immutable snapshot
        for (Pattern noise : config.noisePatterns()) {
            try { if (noise.matcher(finding).find()) return true; }
            catch (Exception ignored) { }
        }
        if ("URL".equals(type) || "ENDPOINT".equals(type)) {
            for (String domain : config.noiseDomains()) {
                if (finding.contains(domain)) return true;
            }
        }
        if ("ENDPOINT".equals(type) || "FILE".equals(type)) {
            for (String prefix : config.modulePrefixes()) {
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
        if (!acceptingResponses.get()) return ResponseReceivedAction.continueWith(responseReceived);
        try {
            executorService.submit(() -> analyzeResponse(responseReceived));
        } catch (RejectedExecutionException e) {
            // The rejection handler has already counted and rate-limited this drop.
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void analyzeResponse(HttpResponseReceived responseReceived) {
        String url = responseReceived.initiatingRequest().url();
        ScannerConfig config = activeConfig.get();
        if (!shouldAnalyze(url, responseReceived, config)) return;
        String body = responseReceived.bodyToString();
        if (body == null || body.isEmpty()) return;
        if (!isMostlyPrintable(body)) return;
        if (!shouldScanResponse(url, body, config)) return;
        log(LogLevel.DEBUG, "Analyzing: " + url);
        HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(
            responseReceived.initiatingRequest(), responseReceived);
        analyzeContent(url, body, reqResp, config);
    }

    @Override
    public void extensionUnloaded() {
        log(LogLevel.INFO, "JS Miner Pro unloading...");
        acceptingResponses.set(false);
        shutdownPool(executorService, "analysis pool");
        drainPendingFindingBatches();
        if (resultsTab != null) {
            resultsTab.saveAllFindings();
            if (clearFindingsOnProjectClose) {
                resultsTab.clearPersistedFindings();
                log(LogLevel.INFO, "Persisted findings cleared on unload.");
            } else {
                log(LogLevel.INFO, "Findings saved on unload.");
            }
        }
        shutdownPool(autoSaveScheduler, "auto-save scheduler");
    }

    private void drainPendingFindingBatches() {
        if (SwingUtilities.isEventDispatchThread()) return;
        try {
            SwingUtilities.invokeAndWait(() -> { });
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log(LogLevel.WARN, "Interrupted while draining pending finding updates.");
        } catch (java.lang.reflect.InvocationTargetException e) {
            log(LogLevel.WARN, "Failed to drain pending finding updates: " + e.getCause());
        }
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
