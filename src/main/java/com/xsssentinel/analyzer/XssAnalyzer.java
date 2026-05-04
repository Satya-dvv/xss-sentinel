package com.xsssentinel.analyzer;

import java.util.ArrayList;
import java.util.List;

public class XssAnalyzer {

    private static final List<String> REFLECTION_MARKERS = List.of(
            "XSS-Sentinel",
            "<script>",
            "onerror=",
            "onload=",
            "javascript:",
            "alert(",
            "<svg",
            "<img"
    );

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

        public AnalysisResult(boolean vulnerable, String payload, String evidence, String parameter, VulnerabilityType type) {
            this.vulnerable = vulnerable;
            this.payload = payload;
            this.evidence = evidence;
            this.parameter = parameter;
            this.type = type;
        }

        public boolean isVulnerable() {
            return vulnerable;
        }

        public String getPayload() {
            return payload;
        }

        public String getEvidence() {
            return evidence;
        }

        public String getParameter() {
            return parameter;
        }

        public VulnerabilityType getType() {
            return type;
        }

        public String toString() {
            return "[" + type + "] Parameter: " + parameter + " | Payload: " + payload + " | Evidence: " + evidence;
        }
    }

    public AnalysisResult analyze(String responseBody, String payload, String parameter) {

        if (responseBody == null || responseBody.isEmpty()) {
            return new AnalysisResult(false, payload, "Empty response", parameter, VulnerabilityType.UNKNOWN);
        }

        if (responseBody.contains("XSS-Sentinel")) {
            String evidence = extractEvidence(responseBody, "XSS-Sentinel");
            VulnerabilityType type = determineType(payload);
            return new AnalysisResult(true, payload, evidence, parameter, type);
        }

        for (String marker : REFLECTION_MARKERS) {
            if (responseBody.contains(marker)) {
                String evidence = extractEvidence(responseBody, marker);
                VulnerabilityType type = determineType(payload);
                return new AnalysisResult(true, payload, evidence, parameter, type);
            }
        }

        return new AnalysisResult(false, payload, "No reflection detected", parameter, VulnerabilityType.UNKNOWN);
    }

    private String extractEvidence(String responseBody, String marker) {
        int index = responseBody.indexOf(marker);
        if (index == -1) {
            return "N/A";
        }
        int start = Math.max(0, index - 30);
        int end = Math.min(responseBody.length(), index + marker.length() + 30);
        return "..." + responseBody.substring(start, end) + "...";
    }

    private VulnerabilityType determineType(String payload) {
        if (payload.startsWith("javascript:") || payload.startsWith("#")) {
            return VulnerabilityType.DOM_BASED;
        }
        if (payload.contains("<script>") || payload.contains("<img") || payload.contains("<svg")) {
            return VulnerabilityType.REFLECTED;
        }
        return VulnerabilityType.UNKNOWN;
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