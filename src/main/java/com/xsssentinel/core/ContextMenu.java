package com.xsssentinel.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.xsssentinel.ui.SentinelPanel;

import javax.swing.*;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

public class ContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final SentinelScanner scanner;
    private final SentinelPanel panel;

    public ContextMenu(MontoyaApi api, SentinelScanner scanner,
                       SentinelPanel panel) {
        this.api = api;
        this.scanner = scanner;
        this.panel = panel;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // Only show in relevant tools
        if (!event.isFromTool(ToolType.PROXY,
                ToolType.TARGET,
                ToolType.REPEATER,
                ToolType.LOGGER)) {
            return menuItems;
        }

        // Get selected requests
        List<HttpRequestResponse> requests =
                event.selectedRequestResponses();

        if (requests.isEmpty()) {
            return menuItems;
        }

        // Main scan menu item
        JMenuItem scanItem = new JMenuItem(
                "XSS-Sentinel — Scan this request");
        scanItem.setIcon(null);
        scanItem.addActionListener(e -> {
            for (HttpRequestResponse reqRes : requests) {
                scanSingleRequest(reqRes);
            }
        });

        // Scan all parameters menu item
        JMenuItem scanAllItem = new JMenuItem(
                "XSS-Sentinel — Scan all parameters");
        scanAllItem.addActionListener(e -> {
            for (HttpRequestResponse reqRes : requests) {
                scanAllParameters(reqRes);
            }
        });

        // Separator
        JSeparator separator = new JSeparator();

        menuItems.add(scanItem);
        menuItems.add(scanAllItem);
        menuItems.add(separator);

        return menuItems;
    }

    private void scanSingleRequest(HttpRequestResponse reqRes) {
        try {
            HttpRequest request = reqRes.request();
            String url = request.url();
            String method = request.method();
            String body = request.bodyToString();
            String contentType = "";

            try {
                contentType = request.headerValue("Content-Type");
                if (contentType == null) contentType = "";
            } catch (Exception ex) {
                contentType = "";
            }

            String queryString = getQueryString(url);

            // Feed into crawler
            scanner.getCrawler().processRequest(
                    url, method, queryString, body, contentType);

            panel.setStatus("Request added — click Quick Scan to test");

            // Show notification
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(null,
                        "<html><b>Request added to XSS-Sentinel!</b><br><br>"
                                + "URL: " + shortenUrl(url) + "<br>"
                                + "Method: " + method + "<br><br>"
                                + "Go to the <b>XSS-Sentinel</b> tab<br>"
                                + "and click <b>Quick Scan</b> to test.</html>",
                        "XSS-Sentinel",
                        JOptionPane.INFORMATION_MESSAGE);
            });

        } catch (Exception e) {
            api.logging().logToError(
                    "Context menu error: " + e.getMessage());
        }
    }

    private void scanAllParameters(HttpRequestResponse reqRes) {
        try {
            HttpRequest request = reqRes.request();
            String url = request.url();

            panel.setStatus("Scanning: " + shortenUrl(url));

            // Trigger full scan on this URL
            new Thread(() -> {
                scanner.crawlAndScan(url,
                        new SentinelPanel.LoginCredentials(
                                "", "", "", "", ""));
            }).start();

            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(null,
                        "<html><b>XSS-Sentinel scan started!</b><br><br>"
                                + "Scanning: " + shortenUrl(url) + "<br><br>"
                                + "Go to the <b>XSS-Sentinel</b> tab<br>"
                                + "to see results in real time.</html>",
                        "XSS-Sentinel",
                        JOptionPane.INFORMATION_MESSAGE);
            });

        } catch (Exception e) {
            api.logging().logToError(
                    "Context menu scan error: " + e.getMessage());
        }
    }

    private String getQueryString(String url) {
        int index = url.indexOf("?");
        if (index == -1) return "";
        return url.substring(index + 1);
    }

    private String shortenUrl(String url) {
        if (url == null) return "";
        if (url.length() > 50) return url.substring(0, 50) + "...";
        return url;
    }
}