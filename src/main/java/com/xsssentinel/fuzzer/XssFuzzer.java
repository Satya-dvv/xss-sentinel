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
            String paramLower = parameter.toLowerCase();

            // Critical — stored or admin area
            if (type == XssAnalyzer.VulnerabilityType.STORED) {
                return "Critical";
            }
            if (urlLower.contains("admin") || urlLower.contains("dashboard")) {
                return "Critical";
            }

            // High — reflected in sensitive areas
            if (type == XssAnalyzer.VulnerabilityType.REFLECTED) {
                if (paramLower.contains("user") || paramLower.contains("email")
                        || paramLower.contains("name")
                        || urlLower.contains("login")
                        || urlLower.contains("account")) {
                    return "High";
                }
                return "High";
            }

            // Medium — DOM based
            if (type == XssAnalyzer.VulnerabilityType.DOM_BASED) {
                return "Medium";
            }

            return "Low";
        }

        private static String generateRemediation(
                XssAnalyzer.VulnerabilityType type, String parameter) {
            StringBuilder sb = new StringBuilder();

            // Base remediation always applies
            sb.append("1. ENCODE OUTPUT: Use HTML entity encoding before ");
            sb.append("rendering '").append(parameter).append("' in the page. ");
            sb.append("Replace <, >, \", ', & with HTML entities.\n\n");

            sb.append("2. VALIDATE INPUT: Whitelist allowed characters for '");
            sb.append(parameter).append("'. ");
            sb.append("Reject or sanitize unexpected characters.\n\n");

            sb.append("3. USE CSP: Implement Content-Security-Policy header: ");
            sb.append("Content-Security-Policy: default-src 'self'\n\n");

            // Type specific remediation
            if (type == XssAnalyzer.VulnerabilityType.REFLECTED) {
                sb.append("4. REFLECTED XSS FIX: Never reflect user input directly ");
                sb.append("into HTML. Use server-side encoding libraries like:\n");
                sb.append("   • Java: OWASP Java Encoder\n");
                sb.append("   • PHP: htmlspecialchars()\n");
                sb.append("   • Python: markupsafe.escape()\n");
                sb.append("   • .NET: HttpUtility.HtmlEncode()\n\n");
                sb.append("5. SET HttpOnly FLAG on session cookies to prevent ");
                sb.append("session theft via XSS.");
            } else if (type == XssAnalyzer.VulnerabilityType.STORED) {
                sb.append("4. STORED XSS FIX: Sanitize ALL user-supplied data ");
                sb.append("BEFORE storing in database AND before rendering.\n");
                sb.append("   Use a sanitization library like DOMPurify.\n\n");
                sb.append("5. CRITICAL: Audit ALL places where '");
                sb.append(parameter);
                sb.append("' value is displayed to other users.");
            } else if (type == XssAnalyzer.VulnerabilityType.DOM_BASED) {
                sb.append("4. DOM XSS FIX: Avoid using dangerous sinks:\n");
                sb.append("   • innerHTML, document.write(), eval()\n");
                sb.append("   • Use textContent or innerText instead\n\n");
                sb.append("5. SANITIZE: Use DOMPurify before assigning ");
                sb.append("user data to DOM elements.");
            }

            return sb.toString();
        }

        private static String detectLocation(String url, String parameter) {
            String urlLower = url.toLowerCase();
            String paramLower = parameter.toLowerCase();

            if (urlLower.contains("search") || paramLower.contains("search")
                    || paramLower.contains("query") || paramLower.equals("q")) {
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
                    + " | " + url + " | Param: " + parameter
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