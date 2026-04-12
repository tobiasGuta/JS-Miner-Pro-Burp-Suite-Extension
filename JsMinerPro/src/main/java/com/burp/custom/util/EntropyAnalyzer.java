package com.burp.custom.util;

import java.util.regex.Pattern;

/**
 * Utility class for analyzing string entropy to detect potential secrets.
 * High entropy strings are more likely to be passwords, API keys, or tokens.
 */
public class EntropyAnalyzer {

    // Minimum length for entropy analysis
    private static final int MIN_LENGTH = 8;
    
    // Entropy thresholds
    private static final double HIGH_ENTROPY_THRESHOLD = 4.5;
    private static final double VERY_HIGH_ENTROPY_THRESHOLD = 5.0;
    
    // Pattern to detect hex strings
    private static final Pattern HEX_PATTERN = Pattern.compile("^[a-fA-F0-9]+$");
    
    // Pattern to detect base64 strings
    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/=]+$");
    
    // Pattern to detect alphanumeric with special chars (common in API keys)
    private static final Pattern API_KEY_PATTERN = Pattern.compile("^[A-Za-z0-9_\\-]+$");

    /**
     * Calculates Shannon entropy of a string.
     * Higher values indicate more randomness (potential secrets).
     * 
     * @param str The string to analyze
     * @return Entropy value (0-8 for ASCII, higher = more random)
     */
    public static double calculateEntropy(String str) {
        if (str == null || str.length() < MIN_LENGTH) {
            return 0.0;
        }

        int[] charCounts = new int[256];
        for (char c : str.toCharArray()) {
            if (c < 256) {
                charCounts[c]++;
            }
        }

        double entropy = 0.0;
        int length = str.length();

        for (int count : charCounts) {
            if (count > 0) {
                double probability = (double) count / length;
                entropy -= probability * (Math.log(probability) / Math.log(2));
            }
        }

        return entropy;
    }

    /**
     * Determines if a string has high entropy (likely a secret).
     */
    public static boolean isHighEntropy(String str) {
        return calculateEntropy(str) >= HIGH_ENTROPY_THRESHOLD;
    }

    /**
     * Determines if a string has very high entropy (very likely a secret).
     */
    public static boolean isVeryHighEntropy(String str) {
        return calculateEntropy(str) >= VERY_HIGH_ENTROPY_THRESHOLD;
    }

    /**
     * Gets the entropy level as a descriptive string.
     */
    public static String getEntropyLevel(String str) {
        double entropy = calculateEntropy(str);
        if (entropy >= VERY_HIGH_ENTROPY_THRESHOLD) {
            return "VERY HIGH";
        } else if (entropy >= HIGH_ENTROPY_THRESHOLD) {
            return "HIGH";
        } else if (entropy >= 3.5) {
            return "MEDIUM";
        } else {
            return "LOW";
        }
    }

    /**
     * Analyzes a string and returns detailed entropy information.
     */
    public static EntropyResult analyze(String str) {
        if (str == null || str.length() < MIN_LENGTH) {
            return new EntropyResult(0.0, "LOW", false, "Too short");
        }

        double entropy = calculateEntropy(str);
        String level = getEntropyLevel(str);
        boolean isSecret = false;
        String type = "Unknown";

        // Identify string type
        if (HEX_PATTERN.matcher(str).matches()) {
            type = "Hex";
            isSecret = str.length() >= 32 && entropy >= 3.5;
        } else if (BASE64_PATTERN.matcher(str).matches()) {
            type = "Base64";
            isSecret = str.length() >= 20 && entropy >= 4.0;
        } else if (API_KEY_PATTERN.matcher(str).matches()) {
            type = "API Key Format";
            isSecret = str.length() >= 16 && entropy >= HIGH_ENTROPY_THRESHOLD;
        } else {
            type = "Mixed";
            isSecret = entropy >= VERY_HIGH_ENTROPY_THRESHOLD;
        }

        return new EntropyResult(entropy, level, isSecret, type);
    }

    /**
     * Quick check if a string looks like a potential secret based on entropy and format.
     */
    public static boolean looksLikeSecret(String str) {
        if (str == null || str.length() < 16) {
            return false;
        }

        double entropy = calculateEntropy(str);
        
        // High entropy strings
        if (entropy >= HIGH_ENTROPY_THRESHOLD) {
            return true;
        }
        
        // Medium entropy but looks like key format
        if (entropy >= 3.5 && str.length() >= 32) {
            if (HEX_PATTERN.matcher(str).matches() || 
                BASE64_PATTERN.matcher(str).matches() ||
                API_KEY_PATTERN.matcher(str).matches()) {
                return true;
            }
        }

        return false;
    }

    /**
     * Result class for detailed entropy analysis.
     */
    public static class EntropyResult {
        public final double entropy;
        public final String level;
        public final boolean likelySecret;
        public final String stringType;

        public EntropyResult(double entropy, String level, boolean likelySecret, String stringType) {
            this.entropy = entropy;
            this.level = level;
            this.likelySecret = likelySecret;
            this.stringType = stringType;
        }

        @Override
        public String toString() {
            return String.format("Entropy: %.2f (%s), Type: %s, Likely Secret: %s", 
                entropy, level, stringType, likelySecret);
        }
    }
}
