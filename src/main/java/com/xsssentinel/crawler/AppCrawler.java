package com.xsssentinel.crawler;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AppCrawler {

    private final Set<String> visitedUrls = new HashSet<>();
    private final List<CrawledInput> discoveredInputs = new ArrayList<>();

    public static class CrawledInput {
        private final String url;
        private final String parameter;
        private final String method;
        private final InputType inputType;

        public enum InputType {
            QUERY_PARAM,
            FORM_FIELD,
            HEADER,
            COOKIE,
            JSON_FIELD
        }

        public CrawledInput(String url, String parameter, String method, InputType inputType) {
            this.url = url;
            this.parameter = parameter;
            this.method = method;
            this.inputType = inputType;
        }

        public String getUrl() { return url; }
        public String getParameter() { return parameter; }
        public String getMethod() { return method; }
        public InputType getInputType() { return inputType; }

        public String toString() {
            return "[" + method + "] " + url + " | Param: " + parameter + " | Type: " + inputType;
        }
    }

    public void processRequest(String url, String method, String queryString, String requestBody, String contentType) {

        if (url == null || visitedUrls.contains(url + method)) {
            return;
        }

        visitedUrls.add(url + method);

        // Extract query parameters from URL
        if (queryString != null && !queryString.isEmpty()) {
            extractQueryParams(url, method, queryString);
        }

        // Extract form fields from POST body
        if (requestBody != null && !requestBody.isEmpty()) {
            if (isFormEncoded(contentType)) {
                extractFormParams(url, method, requestBody);
            } else if (isJson(contentType)) {
                extractJsonParams(url, method, requestBody);
            }
        }
    }

    private void extractQueryParams(String url, String method, String queryString) {
        String[] pairs = queryString.split("&");
        for (String pair : pairs) {
            String[] parts = pair.split("=", 2);
            if (parts.length >= 1 && !parts[0].isEmpty()) {
                discoveredInputs.add(new CrawledInput(
                        url,
                        parts[0],
                        method,
                        CrawledInput.InputType.QUERY_PARAM
                ));
            }
        }
    }

    private void extractFormParams(String url, String method, String body) {
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            String[] parts = pair.split("=", 2);
            if (parts.length >= 1 && !parts[0].isEmpty()) {
                discoveredInputs.add(new CrawledInput(
                        url,
                        parts[0],
                        method,
                        CrawledInput.InputType.FORM_FIELD
                ));
            }
        }
    }

    private void extractJsonParams(String url, String method, String body) {
        String[] tokens = body.split("\"");
        for (int i = 1; i < tokens.length - 1; i += 2) {
            String key = tokens[i].trim();
            if (!key.isEmpty() && !key.startsWith("{") && !key.startsWith("[")) {
                discoveredInputs.add(new CrawledInput(
                        url,
                        key,
                        method,
                        CrawledInput.InputType.JSON_FIELD
                ));
            }
        }
    }

    private boolean isFormEncoded(String contentType) {
        return contentType != null &&
                contentType.toLowerCase().contains("application/x-www-form-urlencoded");
    }

    private boolean isJson(String contentType) {
        return contentType != null &&
                contentType.toLowerCase().contains("application/json");
    }

    public List<CrawledInput> getDiscoveredInputs() {
        return new ArrayList<>(discoveredInputs);
    }

    public Set<String> getVisitedUrls() {
        return new HashSet<>(visitedUrls);
    }

    public void clear() {
        visitedUrls.clear();
        discoveredInputs.clear();
    }

    public int getTotalDiscovered() {
        return discoveredInputs.size();
    }
}