package com.xsssentinel.fuzzer;

import com.xsssentinel.analyzer.XssAnalyzer;
import com.xsssentinel.crawler.AppCrawler;
import com.xsssentinel.payloads.PayloadManager;

import java.util.ArrayList;
import java.util.List;

public class XssFuzzer {

    private final PayloadManager payloadManager;
    private final XssAnalyzer analyzer;

    public static class FuzzResult {
        private final String url;
        private final String parameter;
        private final String payload;
        private final String evidence;
        private final XssAnalyzer.VulnerabilityType type;
        private final boolean vulnerable;
        private final String severity;
        private final String remediation;
        private final String location;

        public FuzzResult(String url, String parameter, String payload,
                          String evidence, XssAnalyzer.VulnerabilityType type,
                          boolean vulnerable) {
            this.url = url;
            this.parameter = parameter;
            this.payload = payload;
            this.evidence = evidence;
            this.type = type;
            this.vulnerable = vulnerable;
            this.severity = calculateSeverity(type, parameter, url);
            this.remediation = generateRemediation(type, parameter);
            this.location = detectLocation(url, parameter);
        }

        private static String calculateSeverity(
                XssAnalyzer.VulnerabilityType type,
                String parameter, String url) {
            String urlLower = url.toLowerCase();

            // Critical — stored XSS or admin area
            if (type == XssAnalyzer.VulnerabilityType.STORED) {
                return "Critical";
            }
            if (urlLower.contains("admin")
                    || urlLower.contains("dashboard")
                    || urlLower.contains("manage")) {
                return "Critical";
            }

            // High — reflected XSS
            if (type == XssAnalyzer.VulnerabilityType.REFLECTED) {
                return "High";
            }

            // Medium — DOM based
            if (type == XssAnalyzer.VulnerabilityType.DOM_BASED) {
                return "Medium";
            }

            // Default
            return "High";
        }

        private static String generateRemediation(
                XssAnalyzer.VulnerabilityType type, String parameter) {
            StringBuilder sb = new StringBuilder();

            sb.append("REMEDIATION GUIDE FOR PARAMETER: '")
                    .append(parameter).append("'\n");
            sb.append("=".repeat(50)).append("\n\n");

            sb.append("1. OUTPUT ENCODING\n");
            sb.append("   Encode all user input before rendering in HTML.\n");
            sb.append("   Replace special characters with HTML entities:\n");
            sb.append("   & → &amp;  < → &lt;  > → &gt;\n");
            sb.append("   \" → &quot;  ' → &#x27;\n\n");

            sb.append("2. INPUT VALIDATION\n");
            sb.append("   Whitelist allowed characters for '")
                    .append(parameter).append("'.\n");
            sb.append("   Reject or sanitize unexpected input.\n\n");

            sb.append("3. CONTENT SECURITY POLICY\n");
            sb.append("   Add this header to all responses:\n");
            sb.append("   Content-Security-Policy: default-src 'self'\n\n");

            if (type == XssAnalyzer.VulnerabilityType.REFLECTED) {
                sb.append("4. REFLECTED XSS SPECIFIC FIX\n");
                sb.append("   Never reflect user input directly into HTML.\n");
                sb.append("   Use encoding libraries:\n");
                sb.append("   • Java:   OWASP Java Encoder\n");
                sb.append("             Encoder.forHtml(input)\n");
                sb.append("   • PHP:    htmlspecialchars($input, ENT_QUOTES)\n");
                sb.append("   • Python: markupsafe.escape(input)\n");
                sb.append("   • .NET:   HttpUtility.HtmlEncode(input)\n\n");
                sb.append("5. SET HttpOnly AND Secure FLAGS\n");
                sb.append("   On all session cookies to prevent theft.\n");
            } else if (type == XssAnalyzer.VulnerabilityType.STORED) {
                sb.append("4. STORED XSS SPECIFIC FIX\n");
                sb.append("   Sanitize ALL user data BEFORE storing\n");
                sb.append("   AND before rendering to other users.\n");
                sb.append("   Use DOMPurify for HTML sanitization.\n\n");
                sb.append("5. AUDIT ALL DISPLAY POINTS\n");
                sb.append("   Check everywhere '").append(parameter)
                        .append("' is displayed to users.\n");
            } else if (type == XssAnalyzer.VulnerabilityType.DOM_BASED) {
                sb.append("4. DOM XSS SPECIFIC FIX\n");
                sb.append("   Avoid dangerous JavaScript sinks:\n");
                sb.append("   ✗ innerHTML, document.write(), eval()\n");
                sb.append("   ✓ Use textContent or innerText instead\n\n");
                sb.append("5. SANITIZE DOM INPUT\n");
                sb.append("   Use DOMPurify before assigning\n");
                sb.append("   user data to any DOM element.\n");
            }

            sb.append("\n6. REFERENCES\n");
            sb.append("   • OWASP XSS Prevention Cheat Sheet\n");
            sb.append("   • https://cheatsheetseries.owasp.org\n");

            return sb.toString();
        }

        private static String detectLocation(String url, String parameter) {
            String urlLower = url.toLowerCase();
            String paramLower = parameter.toLowerCase();

            if (urlLower.contains("search")
                    || paramLower.contains("search")
                    || paramLower.contains("query")
                    || paramLower.equals("q")) {
                return "Search Bar";
            } else if (urlLower.contains("login")
                    || paramLower.contains("user")
                    || paramLower.contains("pass")) {
                return "Login Form";
            } else if (urlLower.contains("comment")
                    || paramLower.contains("comment")
                    || paramLower.contains("message")) {
                return "Comment Field";
            } else if (urlLower.contains("profile")
                    || paramLower.contains("name")
                    || paramLower.contains("bio")) {
                return "Profile Field";
            } else if (urlLower.contains("contact")
                    || paramLower.contains("email")) {
                return "Contact Form";
            } else if (urlLower.contains("register")
                    || urlLower.contains("signup")) {
                return "Registration Form";
            } else if (urlLower.contains("feedback")) {
                return "Feedback Form";
            } else if (urlLower.contains("admin")) {
                return "Admin Panel";
            } else if (paramLower.contains("id")
                    || paramLower.contains("page")
                    || paramLower.contains("content")) {
                return "URL Parameter";
            } else {
                return "Input Field";
            }
        }

        public String getUrl() { return url; }
        public String getParameter() { return parameter; }
        public String getPayload() { return payload; }
        public String getEvidence() { return evidence; }
        public XssAnalyzer.VulnerabilityType getType() { return type; }
        public boolean isVulnerable() { return vulnerable; }
        public String getSeverity() { return severity; }
        public String getRemediation() { return remediation; }
        public String getLocation() { return location; }

        public String toString() {
            return "[" + severity + "] " + location
                    + " | " + url
                    + " | Param: " + parameter
                    + " | Payload: " + payload;
        }
    }

    public interface FuzzCallback {
        String sendPayload(String url, String parameter,
                           String payload, String method);
    }

    public XssFuzzer() {
        this.payloadManager = new PayloadManager();
        this.analyzer = new XssAnalyzer();
    }

    public XssFuzzer(PayloadManager payloadManager) {
        this.payloadManager = payloadManager;
        this.analyzer = new XssAnalyzer();
    }

    public List<FuzzResult> fuzz(AppCrawler.CrawledInput input,
                                 FuzzCallback callback) {
        List<FuzzResult> results = new ArrayList<>();
        List<String> payloads = payloadManager.getAllPayloads();

        for (String payload : payloads) {
            try {
                String response = callback.sendPayload(
                        input.getUrl(),
                        input.getParameter(),
                        payload,
                        input.getMethod()
                );

                if (response == null || response.isEmpty()) continue;

                XssAnalyzer.AnalysisResult result = analyzer.analyze(
                        response, payload, input.getParameter()
                );

                if (result.isVulnerable()) {
                    results.add(new FuzzResult(
                            input.getUrl(),
                            input.getParameter(),
                            payload,
                            result.getEvidence(),
                            result.getType(),
                            true
                    ));
                    break;
                }

            } catch (Exception e) {
                System.err.println("Fuzz error: " + e.getMessage());
            }
        }
        return results;
    }

    public List<FuzzResult> fuzzAll(List<AppCrawler.CrawledInput> inputs,
                                    FuzzCallback callback) {
        List<FuzzResult> all = new ArrayList<>();
        for (AppCrawler.CrawledInput input : inputs) {
            all.addAll(fuzz(input, callback));
        }
        return all;
    }
}