package com.xsssentinel.analyzer;

import com.xsssentinel.payloads.PayloadManager;
import java.util.ArrayList;
import java.util.List;

public class XssAnalyzer {

    public enum VulnerabilityType {
        REFLECTED,
        DOM_BASED,
        STORED,
        UNKNOWN
    }

    public static class AnalysisResult {
        private final boolean vulnerable;
        private final String payload;
        private final String evidence;
        private final String parameter;
        private final VulnerabilityType type;

        public AnalysisResult(boolean vulnerable, String payload,
                              String evidence, String parameter,
                              VulnerabilityType type) {
            this.vulnerable = vulnerable;
            this.payload = payload;
            this.evidence = evidence;
            this.parameter = parameter;
            this.type = type;
        }

        public boolean isVulnerable() { return vulnerable; }
        public String getPayload() { return payload; }
        public String getEvidence() { return evidence; }
        public String getParameter() { return parameter; }
        public VulnerabilityType getType() { return type; }

        public String toString() {
            return "[" + type + "] Parameter: " + parameter
                    + " | Payload: " + payload
                    + " | Evidence: " + evidence;
        }
    }

    public AnalysisResult analyze(String responseBody,
                                  String payload,
                                  String parameter) {

        if (responseBody == null || responseBody.isEmpty()) {
            return new AnalysisResult(false, payload,
                    "Empty response", parameter,
                    VulnerabilityType.UNKNOWN);
        }

        // Step 1 — Check if our unique marker is reflected
        // This is the ONLY reliable confirmation of XSS
        if (responseBody.contains(PayloadManager.MARKER)) {

            // Step 2 — Verify it's actually unescaped HTML
            // Not just the word reflected but actual dangerous tags
            boolean hasUnescapedTag = false;
            String evidence = "";

            // Check for unescaped script tag
            if (responseBody.contains("<script")
                    && responseBody.contains(PayloadManager.MARKER)) {
                hasUnescapedTag = true;
                evidence = extractEvidence(responseBody, "<script");
            }

            // Check for unescaped img tag with onerror
            if (!hasUnescapedTag
                    && responseBody.contains("<img")
                    && responseBody.contains("onerror")
                    && responseBody.contains(PayloadManager.MARKER)) {
                hasUnescapedTag = true;
                evidence = extractEvidence(responseBody, "onerror");
            }

            // Check for unescaped svg tag
            if (!hasUnescapedTag
                    && responseBody.contains("<svg")
                    && responseBody.contains(PayloadManager.MARKER)) {
                hasUnescapedTag = true;
                evidence = extractEvidence(responseBody, "<svg");
            }

            // Check for unescaped event handler
            if (!hasUnescapedTag
                    && (responseBody.contains("onload=")
                    || responseBody.contains("onfocus=")
                    || responseBody.contains("ontoggle="))
                    && responseBody.contains(PayloadManager.MARKER)) {
                hasUnescapedTag = true;
                evidence = extractEvidence(responseBody,
                        PayloadManager.MARKER);
            }

            // Check for unescaped details/input/select tags
            if (!hasUnescapedTag
                    && (responseBody.contains("<details")
                    || responseBody.contains("<input")
                    || responseBody.contains("<select"))
                    && responseBody.contains(PayloadManager.MARKER)) {
                hasUnescapedTag = true;
                evidence = extractEvidence(responseBody,
                        PayloadManager.MARKER);
            }

            if (hasUnescapedTag) {
                VulnerabilityType type = determineType(payload);
                return new AnalysisResult(true, payload,
                        evidence, parameter, type);
            }
        }

        // Not vulnerable
        return new AnalysisResult(false, payload,
                "No XSS reflection detected", parameter,
                VulnerabilityType.UNKNOWN);
    }

    private VulnerabilityType determineType(String payload) {
        String p = payload.toLowerCase();
        if (p.startsWith("#")
                || p.contains("document.")
                || p.contains("innerhtml")
                || p.contains("window.")) {
            return VulnerabilityType.DOM_BASED;
        }
        if (p.contains("<script")
                || p.contains("<img")
                || p.contains("<svg")
                || p.contains("<iframe")
                || p.contains("onerror")
                || p.contains("onload")
                || p.contains("onfocus")
                || p.contains("ontoggle")) {
            return VulnerabilityType.REFLECTED;
        }
        return VulnerabilityType.REFLECTED;
    }

    private String extractEvidence(String responseBody, String marker) {
        int index = responseBody.toLowerCase()
                .indexOf(marker.toLowerCase());
        if (index == -1) return "N/A";
        int start = Math.max(0, index - 40);
        int end = Math.min(responseBody.length(),
                index + marker.length() + 40);
        return "..." + responseBody.substring(start, end) + "...";
    }

    public List<String> getSuggestedPayloads(String responseBody) {
        List<String> suggested = new ArrayList<>();
        if (responseBody.contains("<input")) {
            suggested.add("<img src=x onerror=alert('"
                    + PayloadManager.MARKER + "')>");
        }
        if (responseBody.contains("value=")) {
            suggested.add("'\"><script>alert('"
                    + PayloadManager.MARKER + "')</script>");
        }
        if (responseBody.contains("href=")) {
            suggested.add("#<img src=x onerror=alert('"
                    + PayloadManager.MARKER + "')>");
        }
        return suggested;
    }
}