package com.xsssentinel.core;

import com.xsssentinel.crawler.AppCrawler;
import com.xsssentinel.fuzzer.XssFuzzer;
import com.xsssentinel.ui.SentinelPanel;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SentinelScanner {

    private final MontoyaApi api;
    private final AppCrawler crawler;
    private final XssFuzzer fuzzer;
    private final SentinelPanel panel;
    private boolean scanning = false;

    private static final int MAX_PAGES = 10;
    private static final int TIMEOUT = 10000;

    // Single strong polyglot payload for quick test
    private static final String QUICK_TEST_PAYLOAD =
            "<script>alert('XSS-Sentinel')</script>";
    private static final String QUICK_TEST_PAYLOAD_2 =
            "\"><script>alert('XSS-Sentinel')</script>";
    private static final String QUICK_TEST_PAYLOAD_3 =
            "<img src=x onerror=alert('XSS-Sentinel')>";
    private static final String QUICK_TEST_PAYLOAD_4 =
            "'><svg onload=alert('XSS-Sentinel')>";
    private static final String QUICK_TEST_PAYLOAD_5 =
            "javascript:alert('XSS-Sentinel')";

    public SentinelScanner(MontoyaApi api, SentinelPanel panel,
                           com.xsssentinel.payloads.PayloadManager payloadManager) {
        this.api = api;
        this.panel = panel;
        this.crawler = new AppCrawler();
        this.fuzzer = new XssFuzzer(payloadManager);
    }

    public void processProxyRequest(HttpRequestResponse requestResponse) {
        try {
            HttpRequest request = requestResponse.request();
            if (request == null) return;
            String url = request.url();
            String method = request.method();
            String body = request.bodyToString();
            String contentType = getContentType(request);
            String queryString = getQueryString(url);
            crawler.processRequest(url, method, queryString, body, contentType);
            panel.incrementScanned();
        } catch (Exception e) {
            api.logging().logToError("Crawler error: " + e.getMessage());
        }
    }

    // Quick Test — tests URL parameters directly with fast payloads
    public void quickTest(String targetUrl) {
        if (scanning) {
            panel.setStatus("Scan already in progress...");
            return;
        }

        scanning = true;
        panel.setStatus("Quick Test started on: " + shortenUrl(targetUrl));

        new Thread(() -> {
            try {
                // Extract parameters directly from URL
                String queryString = getQueryString(targetUrl);

                if (queryString.isEmpty()) {
                    panel.setStatus("No parameters found in URL — "
                            + "try Quick Scan to crawl the site");
                    scanning = false;
                    return;
                }

                // Parse parameters
                List<String> parameters = new ArrayList<>();
                String[] pairs = queryString.split("&");
                for (String pair : pairs) {
                    String[] parts = pair.split("=", 2);
                    if (parts.length >= 1 && !parts[0].isEmpty()) {
                        parameters.add(parts[0]);
                    }
                }

                api.logging().logToOutput("Quick Test - Found "
                        + parameters.size() + " parameters in URL");
                panel.setStatus("Testing " + parameters.size()
                        + " parameters with quick payloads...");

                // Test each parameter with quick payloads
                List<String> quickPayloads = new ArrayList<>();
                quickPayloads.add(QUICK_TEST_PAYLOAD);
                quickPayloads.add(QUICK_TEST_PAYLOAD_2);
                quickPayloads.add(QUICK_TEST_PAYLOAD_3);
                quickPayloads.add(QUICK_TEST_PAYLOAD_4);
                quickPayloads.add(QUICK_TEST_PAYLOAD_5);

                int found = 0;
                for (String parameter : parameters) {
                    for (String payload : quickPayloads) {
                        String response = sendRequest(
                                targetUrl, parameter, payload, "GET", "");

                        if (response == null || response.isEmpty()) continue;

                        com.xsssentinel.analyzer.XssAnalyzer analyzer =
                                new com.xsssentinel.analyzer.XssAnalyzer();
                        com.xsssentinel.analyzer.XssAnalyzer.AnalysisResult result =
                                analyzer.analyze(response, payload, parameter);

                        if (result.isVulnerable()) {
                            XssFuzzer.FuzzResult fuzzResult =
                                    new XssFuzzer.FuzzResult(
                                            targetUrl, parameter, payload,
                                            result.getEvidence(),
                                            result.getType(), true);
                            panel.addResult(fuzzResult);
                            found++;
                            api.logging().logToOutput(
                                    "Quick Test FOUND: " + parameter
                                            + " with payload: " + payload);
                            break; // Move to next parameter
                        }
                    }
                }

                if (found == 0) {
                    panel.setStatus("Quick Test complete - No XSS found. "
                            + "Try Quick Scan for deeper testing.");
                } else {
                    panel.setStatus("Quick Test complete - Found "
                            + found + " vulnerabilities!");
                }

            } catch (Exception e) {
                api.logging().logToError(
                        "Quick Test error: " + e.getMessage());
                panel.setStatus("Quick Test error - " + e.getMessage());
            } finally {
                scanning = false;
            }
        }).start();
    }

    public void crawlAndScan(String targetUrl,
                             SentinelPanel.LoginCredentials creds) {
        if (scanning) {
            panel.setStatus("Scan already in progress...");
            return;
        }

        scanning = true;
        crawler.clear();

        new Thread(() -> {
            try {
                String sessionCookie = "";
                if (creds.hasCredentials()) {
                    panel.setStatus("Logging in to: " + creds.loginUrl);
                    sessionCookie = performLogin(creds);
                    if (sessionCookie.isEmpty()) {
                        panel.setStatus("Login failed - check credentials");
                        scanning = false;
                        return;
                    }
                    api.logging().logToOutput("Login successful");
                    panel.setStatus("Login successful - starting crawl...");
                }

                panel.setStatus("Starting crawl of: " + targetUrl);
                Set<String> visited = new HashSet<>();
                List<String> queue = new ArrayList<>();
                queue.add(targetUrl);
                String baseDomain = getBaseDomain(targetUrl);
                int pageCount = 0;

                // Also test URL parameters directly if present
                String directQuery = getQueryString(targetUrl);
                if (!directQuery.isEmpty()) {
                    crawler.processRequest(targetUrl, "GET",
                            directQuery, "", "");
                    panel.incrementScanned();
                    api.logging().logToOutput(
                            "Added direct URL params: " + directQuery);
                }

                while (!queue.isEmpty() && pageCount < MAX_PAGES) {
                    String currentUrl = queue.remove(0);
                    if (visited.contains(currentUrl)) continue;
                    visited.add(currentUrl);
                    pageCount++;

                    panel.setStatus("Crawling " + pageCount + "/"
                            + MAX_PAGES + ": " + shortenUrl(currentUrl));

                    String html = fetchPage(currentUrl, sessionCookie);
                    if (html == null || html.isEmpty()) continue;

                    String queryString = getQueryString(currentUrl);
                    if (!queryString.isEmpty()) {
                        crawler.processRequest(currentUrl, "GET",
                                queryString, "", "");
                        panel.incrementScanned();
                    }

                    extractFormInputs(html, currentUrl);

                    List<String> links = extractLinks(
                            html, currentUrl, baseDomain);
                    for (String link : links) {
                        if (!visited.contains(link)) {
                            queue.add(link);
                        }
                    }
                }

                List<AppCrawler.CrawledInput> inputs =
                        crawler.getDiscoveredInputs();
                api.logging().logToOutput("Discovered "
                        + inputs.size() + " inputs");

                if (inputs.isEmpty()) {
                    panel.setStatus("No inputs found - "
                            + "try browsing manually through Burp proxy");
                    scanning = false;
                    return;
                }

                panel.setStatus("Testing " + inputs.size()
                        + " inputs for XSS...");
                int count = 0;
                String cookie = sessionCookie;

                for (AppCrawler.CrawledInput input : inputs) {
                    while (panel.isPaused()) {
                        try {
                            Thread.sleep(500);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }

                    count++;
                    panel.setStatus("Testing " + count + "/"
                            + inputs.size() + " - "
                            + input.getParameter()
                            + " @ " + shortenUrl(input.getUrl()));

                    List<XssFuzzer.FuzzResult> results = fuzzer.fuzz(
                            input,
                            (url, parameter, payload, method) ->
                                    sendRequest(url, parameter,
                                            payload, method, cookie)
                    );

                    if (!results.isEmpty()) {
                        panel.addResults(results);
                    }
                }

                panel.setStatus("Scan complete - "
                        + inputs.size() + " inputs tested");

            } catch (Exception e) {
                api.logging().logToError("Scan error: " + e.getMessage());
                panel.setStatus("Scan error - " + e.getMessage());
            } finally {
                scanning = false;
            }
        }).start();
    }

    private String performLogin(SentinelPanel.LoginCredentials creds) {
        try {
            URL url = new URL(creds.loginUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type",
                    "application/x-www-form-urlencoded");
            conn.setRequestProperty("User-Agent",
                    "Mozilla/5.0 (XSS-Sentinel Scanner)");
            String body = creds.usernameParam + "="
                    + creds.username + "&"
                    + creds.passwordParam + "="
                    + creds.password;
            conn.getOutputStream().write(body.getBytes());
            String cookie = conn.getHeaderField("Set-Cookie");
            return cookie != null ? cookie : "";
        } catch (Exception e) {
            api.logging().logToError("Login error: " + e.getMessage());
            return "";
        }
    }

    private String fetchPage(String urlStr, String cookie) {
        try {
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("User-Agent",
                    "Mozilla/5.0 (XSS-Sentinel Scanner)");
            conn.setRequestProperty("Accept",
                    "text/html,application/xhtml+xml");
            if (cookie != null && !cookie.isEmpty()) {
                conn.setRequestProperty("Cookie", cookie);
            }
            if (conn.getResponseCode() != 200) return "";
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            reader.close();
            return sb.toString();
        } catch (Exception e) {
            api.logging().logToError("Fetch error: " + e.getMessage());
            return "";
        }
    }

    private void extractFormInputs(String html, String pageUrl) {
        Pattern formPattern = Pattern.compile(
                "<form[^>]*>([\\s\\S]*?)</form>",
                Pattern.CASE_INSENSITIVE);
        Pattern inputPattern = Pattern.compile(
                "<input[^>]*name=[\"']?([^\"'>\\s]+)[\"']?",
                Pattern.CASE_INSENSITIVE);
        Pattern actionPattern = Pattern.compile(
                "<form[^>]*action=[\"']?([^\"'>\\s]*)[\"']?",
                Pattern.CASE_INSENSITIVE);
        Pattern methodPattern = Pattern.compile(
                "<form[^>]*method=[\"']?([^\"'>\\s]*)[\"']?",
                Pattern.CASE_INSENSITIVE);

        Matcher formMatcher = formPattern.matcher(html);
        while (formMatcher.find()) {
            String formHtml = formMatcher.group(1);
            String action = pageUrl;
            String method = "GET";

            Matcher actionMatcher = actionPattern.matcher(
                    formMatcher.group(0));
            if (actionMatcher.find()
                    && !actionMatcher.group(1).isEmpty()) {
                action = resolveUrl(pageUrl, actionMatcher.group(1));
            }

            Matcher methodMatcher = methodPattern.matcher(
                    formMatcher.group(0));
            if (methodMatcher.find()) {
                method = methodMatcher.group(1).toUpperCase();
            }

            Matcher inputMatcher = inputPattern.matcher(formHtml);
            while (inputMatcher.find()) {
                String paramName = inputMatcher.group(1);
                if (paramName != null && !paramName.isEmpty()) {
                    String finalAction = action;
                    String finalMethod = method;
                    crawler.processRequest(
                            finalAction, finalMethod,
                            finalMethod.equals("GET")
                                    ? paramName + "=test" : "",
                            finalMethod.equals("POST")
                                    ? paramName + "=test" : "",
                            finalMethod.equals("POST")
                                    ? "application/x-www-form-urlencoded"
                                    : "");
                    panel.incrementScanned();
                    api.logging().logToOutput("Found input: "
                            + paramName + " @ " + finalAction);
                }
            }
        }
    }

    private List<String> extractLinks(String html,
                                      String baseUrl,
                                      String baseDomain) {
        List<String> links = new ArrayList<>();
        Pattern pattern = Pattern.compile(
                "href=[\"']([^\"'#]+)[\"']",
                Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(html);
        while (matcher.find()) {
            String href = matcher.group(1).trim();
            if (href.isEmpty() || href.startsWith("javascript:")
                    || href.startsWith("mailto:")) continue;
            String fullUrl = resolveUrl(baseUrl, href);
            if (fullUrl != null && fullUrl.contains(baseDomain)) {
                links.add(fullUrl);
            }
        }
        return links;
    }

    private String resolveUrl(String base, String relative) {
        try {
            if (relative.startsWith("http")) return relative;
            URL baseUrl = new URL(base);
            URL resolved = new URL(baseUrl, relative);
            return resolved.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private String getBaseDomain(String url) {
        try {
            return new URL(url).getHost();
        } catch (Exception e) {
            return url;
        }
    }

    private String sendRequest(String url, String parameter,
                               String payload, String method,
                               String cookie) {
        try {
            URL parsedUrl = new URL(url);
            String host = parsedUrl.getHost();
            int port = parsedUrl.getPort();
            boolean isHttps = parsedUrl.getProtocol()
                    .equalsIgnoreCase("https");

            if (port == -1) {
                port = isHttps ? 443 : 80;
            }

            String path = parsedUrl.getPath();
            if (path == null || path.isEmpty()) path = "/";

            String existingQuery = parsedUrl.getQuery();
            StringBuilder newQuery = new StringBuilder();
            boolean found = false;

            if (existingQuery != null && !existingQuery.isEmpty()) {
                for (String pair : existingQuery.split("&")) {
                    String[] parts = pair.split("=", 2);
                    if (newQuery.length() > 0) newQuery.append("&");
                    if (parts[0].equals(parameter)) {
                        newQuery.append(parameter)
                                .append("=")
                                .append(payload);
                        found = true;
                    } else {
                        newQuery.append(pair);
                    }
                }
            }

            if (!found) {
                if (newQuery.length() > 0) newQuery.append("&");
                newQuery.append(parameter).append("=").append(payload);
            }

            String requestLine;
            String requestBody = "";

            if (method.equalsIgnoreCase("GET")) {
                String fullPath = path + "?" + newQuery;
                requestLine = "GET " + fullPath + " HTTP/1.1";
            } else {
                requestLine = "POST " + path + " HTTP/1.1";
                requestBody = parameter + "=" + payload;
            }

            StringBuilder rawRequest = new StringBuilder();
            rawRequest.append(requestLine).append("\r\n");
            rawRequest.append("Host: ").append(host).append("\r\n");
            rawRequest.append("User-Agent: Mozilla/5.0 ")
                    .append("(XSS-Sentinel Scanner)\r\n");
            rawRequest.append("Accept: text/html,application/xhtml+xml\r\n");
            rawRequest.append("Connection: close\r\n");

            if (cookie != null && !cookie.isEmpty()) {
                rawRequest.append("Cookie: ").append(cookie).append("\r\n");
            }

            if (method.equalsIgnoreCase("POST")) {
                rawRequest.append("Content-Type: ")
                        .append("application/x-www-form-urlencoded\r\n");
                rawRequest.append("Content-Length: ")
                        .append(requestBody.length()).append("\r\n");
            }

            rawRequest.append("\r\n");

            if (!requestBody.isEmpty()) {
                rawRequest.append(requestBody);
            }

            api.logging().logToOutput("Testing ["
                    + method + "]: " + host + path
                    + "?" + newQuery);

            HttpService service = HttpService.httpService(
                    host, port, isHttps);
            HttpRequest request = HttpRequest.httpRequest(
                    service, rawRequest.toString());

            HttpRequestResponse response =
                    api.http().sendRequest(request);

            if (response == null || response.response() == null) {
                return "";
            }

            return response.response().bodyToString();

        } catch (Exception e) {
            api.logging().logToError(
                    "Request error: " + e.getMessage());
            return "";
        }
    }

    private String getQueryString(String url) {
        int index = url.indexOf("?");
        if (index == -1) return "";
        return url.substring(index + 1);
    }

    private String getContentType(HttpRequest request) {
        try {
            String ct = request.headerValue("Content-Type");
            return ct != null ? ct : "";
        } catch (Exception e) {
            return "";
        }
    }

    private String shortenUrl(String url) {
        if (url == null) return "";
        if (url.length() > 50) return url.substring(0, 50) + "...";
        return url;
    }

    public void clearData() {
        crawler.clear();
        panel.setStatus("Data cleared - Ready");
    }

    public boolean isScanning() {
        return scanning;
    }

    public AppCrawler getCrawler() {
        return crawler;
    }
}