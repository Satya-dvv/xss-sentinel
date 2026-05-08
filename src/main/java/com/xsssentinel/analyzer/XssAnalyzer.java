package com.xsssentinel.analyzer;

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

        String responseLower = responseBody.toLowerCase();

        // Check 1 — XSS-Sentinel marker reflected
        if (responseBody.contains("XSS-Sentinel")) {
            String evidence = extractEvidence(
                    responseBody, "XSS-Sentinel");
            VulnerabilityType type = determineType(payload);
            return new AnalysisResult(true, payload,
                    evidence, parameter, type);
        }

        // Check 2 — Raw payload reflected
        if (responseBody.contains(payload)) {
            String evidence = extractEvidence(responseBody, payload);
            VulnerabilityType type = determineType(payload);
            return new AnalysisResult(true, payload,
                    evidence, parameter, type);
        }

        // Check 3 — Decoded payload reflected
        String decoded = decodePayload(payload);
        if (!decoded.equals(payload) && responseBody.contains(decoded)) {
            String evidence = extractEvidence(responseBody, decoded);
            VulnerabilityType type = determineType(payload);
            return new AnalysisResult(true, payload,
                    evidence, parameter, type);
        }

        // Check 4 — Dangerous tags reflected
        List<String> dangerousTags = new ArrayList<>();
        dangerousTags.add("<script");
        dangerousTags.add("onerror=");
        dangerousTags.add("onload=");
        dangerousTags.add("onclick=");
        dangerousTags.add("onfocus=");
        dangerousTags.add("onmouseover=");
        dangerousTags.add("<svg");
        dangerousTags.add("<img");
        dangerousTags.add("<iframe");
        dangerousTags.add("javascript:");
        dangerousTags.add("alert(");
        dangerousTags.add("alert`");

        // Only flag if payload contains the tag AND response contains it
        for (String tag : dangerousTags) {
            if (payload.toLowerCase().contains(tag.toLowerCase())
                    && responseLower.contains(tag.toLowerCase())) {
                String evidence = extractEvidence(responseBody, tag);
                VulnerabilityType type = determineType(payload);
                return new AnalysisResult(true, payload,
                        evidence, parameter, type);
            }
        }

        // Check 5 — Parameter value reflected unsanitized
        // If response contains key parts of payload unencoded
        if (payload.contains("<") && responseLower.contains("<script")) {
            String evidence = extractEvidence(responseBody, "<script");
            return new AnalysisResult(true, payload,
                    evidence, parameter, VulnerabilityType.REFLECTED);
        }

        if (payload.contains("onerror") && responseLower.contains("onerror")) {
            String evidence = extractEvidence(responseBody, "onerror");
            return new AnalysisResult(true, payload,
                    evidence, parameter, VulnerabilityType.REFLECTED);
        }

        return new AnalysisResult(false, payload,
                "No reflection detected", parameter,
                VulnerabilityType.UNKNOWN);
    }

    private String decodePayload(String payload) {
        return payload
                .replace("%3C", "<")
                .replace("%3E", ">")
                .replace("%22", "\"")
                .replace("%27", "'")
                .replace("%2F", "/")
                .replace("%3c", "<")
                .replace("%3e", ">")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#x27;", "'");
    }

    private VulnerabilityType determineType(String payload) {
        String p = payload.toLowerCase();
        if (p.startsWith("javascript:")
                || p.startsWith("#")
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
                || p.contains("alert(")) {
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
            suggested.add("<img src=x onerror=alert('XSS-Sentinel')>");
        }
        if (responseBody.contains("value=")) {
            suggested.add("'\"><script>alert('XSS-Sentinel')</script>");
        }
        if (responseBody.contains("href=")) {
            suggested.add("javascript:alert('XSS-Sentinel')");
        }
        return suggested;
    }
}