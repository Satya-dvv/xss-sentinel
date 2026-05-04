package com.xsssentinel;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.xsssentinel.core.SentinelScanner;
import com.xsssentinel.ui.SentinelPanel;

public class XssSentinel implements BurpExtension {

    private static final String EXTENSION_NAME = "XSS-Sentinel";
    private static final String VERSION = "1.0.0";

    private SentinelScanner scanner;
    private SentinelPanel panel;

    @Override
    public void initialize(MontoyaApi api) {

        api.extension().setName(EXTENSION_NAME + " v" + VERSION);

        api.logging().logToOutput("==============================================");
        api.logging().logToOutput(" XSS-Sentinel v" + VERSION + " loaded");
        api.logging().logToOutput(" Intelligent XSS Scanner for Burp Suite");
        api.logging().logToOutput("==============================================");

        // Initialize UI
        panel = new SentinelPanel();

        // Pass API to panel for Repeater support
        panel.setApi(api);

        // Initialize scanner
        scanner = new SentinelScanner(api, panel);

        // Connect buttons to scanner
        panel.setCrawlCallback((targetUrl, creds) -> {
            api.logging().logToOutput("Scan triggered: " + targetUrl);
            api.logging().logToOutput("Auth: "
                    + (creds.hasCredentials() ? "YES" : "NO"));
            scanner.crawlAndScan(targetUrl, creds);
        });

        // Register UI tab
        api.userInterface().registerSuiteTab(
                EXTENSION_NAME, panel.getPanel());

        // Passive proxy monitoring
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(
                    HttpRequestToBeSent requestToBeSent) {
                try {
                    HttpRequestResponse dummy = HttpRequestResponse
                            .httpRequestResponse(requestToBeSent, null);
                    scanner.processProxyRequest(dummy);
                } catch (Exception e) {
                    api.logging().logToError(
                            "Handler error: " + e.getMessage());
                }
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(
                    HttpResponseReceived responseReceived) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });

        api.extension().registerUnloadingHandler(() ->
                api.logging().logToOutput("XSS-Sentinel unloaded"));

        panel.setStatus(
                "Ready — Enter URL, choose Quick Scan or Auth Scan");
    }
}