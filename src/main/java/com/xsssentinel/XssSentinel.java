package com.xsssentinel;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.xsssentinel.core.ContextMenu;
import com.xsssentinel.core.SentinelScanner;
import com.xsssentinel.payloads.PayloadManager;
import com.xsssentinel.ui.PayloadManagerPanel;
import com.xsssentinel.ui.SentinelPanel;

import javax.swing.*;

public class XssSentinel implements BurpExtension {

    private static final String EXTENSION_NAME = "XSS-Sentinel";
    private static final String VERSION = "1.1.1";

    private SentinelScanner scanner;
    private SentinelPanel panel;

    @Override
    public void initialize(MontoyaApi api) {

        api.extension().setName(EXTENSION_NAME + " v" + VERSION);

        api.logging().logToOutput("==============================================");
        api.logging().logToOutput(" XSS-Sentinel v" + VERSION + " loaded");
        api.logging().logToOutput(" Intelligent XSS Scanner for Burp Suite");
        api.logging().logToOutput("==============================================");

        // Initialize shared PayloadManager
        PayloadManager payloadManager = new PayloadManager();

        // Initialize UI panels
        panel = new SentinelPanel();
        panel.setApi(api);

        // Initialize Payload Manager Panel
        PayloadManagerPanel payloadManagerPanel =
                new PayloadManagerPanel(payloadManager);

        // Initialize scanner with shared PayloadManager
        scanner = new SentinelScanner(api, panel, payloadManager);

        // Connect Quick Test button
        panel.setQuickTestCallback(() -> {
            String targetUrl = panel.getTargetUrl();
            api.logging().logToOutput(
                    "Quick Test triggered: " + targetUrl);
            scanner.quickTest(targetUrl);
        });

        // Connect Quick Scan and Auth Scan buttons
        panel.setCrawlCallback((targetUrl, creds) -> {
            api.logging().logToOutput("Scan triggered: " + targetUrl);
            api.logging().logToOutput("Auth: "
                    + (creds.hasCredentials() ? "YES" : "NO"));
            scanner.crawlAndScan(targetUrl, creds);
        });

        // Connect pause/resume
        panel.setPauseCallback(() -> panel.setPaused(true));
        panel.setResumeCallback(() -> panel.setPaused(false));

        // Create tabbed panel
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setFont(new java.awt.Font("SansSerif",
                java.awt.Font.PLAIN, 12));

        // Tab 1 - Scanner
        tabbedPane.addTab("Scanner", panel.getPanel());

        // Tab 2 - Payload Manager
        tabbedPane.addTab("Payload Manager",
                payloadManagerPanel.getPanel());

        // Register combined UI tab
        api.userInterface().registerSuiteTab(
                EXTENSION_NAME, tabbedPane);

        // Register right-click context menu
        api.userInterface().registerContextMenuItemsProvider(
                new ContextMenu(api, scanner, panel));

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
                "Ready - Paste URL with params for Quick Test, "
                        + "or use Quick Scan to crawl entire site");
    }
}