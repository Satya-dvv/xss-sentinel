package com.xsssentinel.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.xsssentinel.fuzzer.XssFuzzer;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

public class SentinelPanel {

    private final JPanel mainPanel;
    private final DefaultTableModel tableModel;
    private final JTable resultsTable;
    private final JLabel statusLabel;
    private final JLabel statsLabel;
    private final JTextField urlField;
    private final JTextField usernameField;
    private final JPasswordField passwordField;
    private final JTextField loginUrlField;
    private final JTextField usernameParamField;
    private final JTextField passwordParamField;
    private final JPanel authPanel;
    private int totalScanned = 0;
    private int totalVulnerable = 0;
    private BiConsumer<String, LoginCredentials> crawlCallback;
    private MontoyaApi api;

    // Store full result data separately
    private final List<XssFuzzer.FuzzResult> resultData = new ArrayList<>();

    public static class LoginCredentials {
        public final String loginUrl;
        public final String username;
        public final String password;
        public final String usernameParam;
        public final String passwordParam;

        public LoginCredentials(String loginUrl, String username,
                                String password, String usernameParam,
                                String passwordParam) {
            this.loginUrl = loginUrl;
            this.username = username;
            this.password = password;
            this.usernameParam = usernameParam;
            this.passwordParam = passwordParam;
        }

        public boolean hasCredentials() {
            return username != null && !username.isEmpty()
                    && password != null && !password.isEmpty();
        }
    }

    public void setApi(MontoyaApi api) {
        this.api = api;
    }

    public SentinelPanel() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBackground(Color.WHITE);

        // ── Header ──────────────────────────────────────────
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(new Color(35, 35, 35));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(10, 15, 10, 15));

        JLabel titleLabel = new JLabel(
                "XSS-Sentinel — Intelligent XSS Scanner");
        titleLabel.setForeground(Color.WHITE);
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 16));

        statsLabel = new JLabel("Scanned: 0 | Vulnerable: 0");
        statsLabel.setForeground(new Color(180, 180, 180));
        statsLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));

        headerPanel.add(titleLabel, BorderLayout.WEST);
        headerPanel.add(statsLabel, BorderLayout.EAST);

        // ── URL Row ──────────────────────────────────────────
        JPanel urlRow = new JPanel(new BorderLayout(8, 0));
        urlRow.setBackground(new Color(50, 50, 50));
        urlRow.setBorder(BorderFactory.createEmptyBorder(8, 15, 4, 15));

        JLabel urlLabel = makeLabel("Target URL:");
        urlLabel.setPreferredSize(new Dimension(80, 28));

        urlField = new JTextField("http://");
        styleTextField(urlField);

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        buttonRow.setBackground(new Color(50, 50, 50));

        JButton quickScanButton = new JButton("Quick Scan");
        quickScanButton.setFont(new Font("SansSerif", Font.BOLD, 12));
        quickScanButton.setBackground(new Color(0, 153, 76));
        quickScanButton.setForeground(Color.WHITE);
        quickScanButton.setOpaque(true);
        quickScanButton.setBorderPainted(false);
        quickScanButton.setPreferredSize(new Dimension(120, 28));
        quickScanButton.setToolTipText(
                "Scan without login — for public/test apps");

        JButton authScanButton = new JButton("Auth Scan");
        authScanButton.setFont(new Font("SansSerif", Font.BOLD, 12));
        authScanButton.setBackground(new Color(255, 102, 0));
        authScanButton.setForeground(Color.WHITE);
        authScanButton.setOpaque(true);
        authScanButton.setBorderPainted(false);
        authScanButton.setPreferredSize(new Dimension(120, 28));
        authScanButton.setToolTipText("Scan with login credentials");

        buttonRow.add(quickScanButton);
        buttonRow.add(authScanButton);

        urlRow.add(urlLabel, BorderLayout.WEST);
        urlRow.add(urlField, BorderLayout.CENTER);
        urlRow.add(buttonRow, BorderLayout.EAST);

        // ── Auth Panel ───────────────────────────────────────
        authPanel = new JPanel(new GridBagLayout());
        authPanel.setBackground(new Color(45, 45, 45));
        authPanel.setBorder(BorderFactory.createEmptyBorder(6, 15, 6, 15));
        authPanel.setVisible(false);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 5, 3, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        authPanel.add(makeLabel("Login URL:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        loginUrlField = new JTextField("http://site.com/login");
        styleTextField(loginUrlField);
        authPanel.add(loginUrlField, gbc);
        gbc.gridx = 2; gbc.weightx = 0;
        authPanel.add(makeLabel("User Param:"), gbc);
        gbc.gridx = 3; gbc.weightx = 0.3;
        usernameParamField = new JTextField("username");
        styleTextField(usernameParamField);
        authPanel.add(usernameParamField, gbc);
        gbc.gridx = 4; gbc.weightx = 0;
        authPanel.add(makeLabel("Pass Param:"), gbc);
        gbc.gridx = 5; gbc.weightx = 0.3;
        passwordParamField = new JTextField("password");
        styleTextField(passwordParamField);
        authPanel.add(passwordParamField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        authPanel.add(makeLabel("Username:"), gbc);
        gbc.gridx = 1; gbc.weightx = 0.5;
        usernameField = new JTextField();
        styleTextField(usernameField);
        authPanel.add(usernameField, gbc);
        gbc.gridx = 2; gbc.weightx = 0;
        authPanel.add(makeLabel("Password:"), gbc);
        gbc.gridx = 3; gbc.weightx = 0.5;
        passwordField = new JPasswordField();
        styleTextField(passwordField);
        authPanel.add(passwordField, gbc);
        gbc.gridx = 4; gbc.weightx = 0;
        JLabel authNote = makeLabel("Fill above then click Auth Scan");
        authNote.setForeground(new Color(255, 180, 0));
        authPanel.add(authNote, gbc);

        // ── Button Actions ────────────────────────────────────
        quickScanButton.addActionListener(e -> {
            String url = urlField.getText().trim();
            if (!validateUrl(url)) return;
            authPanel.setVisible(false);
            mainPanel.revalidate();
            resultData.clear();
            if (crawlCallback != null) {
                crawlCallback.accept(url,
                        new LoginCredentials("", "", "", "", ""));
            }
        });

        authScanButton.addActionListener(e -> {
            String url = urlField.getText().trim();
            if (!validateUrl(url)) return;
            if (!authPanel.isVisible()) {
                authPanel.setVisible(true);
                mainPanel.revalidate();
                setStatus("Fill credentials then click Auth Scan again");
                return;
            }
            LoginCredentials creds = new LoginCredentials(
                    loginUrlField.getText().trim(),
                    usernameField.getText().trim(),
                    new String(passwordField.getPassword()),
                    usernameParamField.getText().trim(),
                    passwordParamField.getText().trim()
            );
            if (!creds.hasCredentials()) {
                JOptionPane.showMessageDialog(mainPanel,
                        "Please enter username and password!",
                        "Missing Credentials", JOptionPane.WARNING_MESSAGE);
                return;
            }
            resultData.clear();
            if (crawlCallback != null) {
                crawlCallback.accept(url, creds);
            }
        });

        // ── Top Panel ────────────────────────────────────────
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(headerPanel, BorderLayout.NORTH);
        topPanel.add(urlRow, BorderLayout.CENTER);
        topPanel.add(authPanel, BorderLayout.SOUTH);

        // ── Results Table ────────────────────────────────────
        // Columns: #, Location, URL, Parameter, XSS Type, Severity, Actions
        String[] columns = {
                "#", "Location", "URL", "Parameter",
                "XSS Type", "Severity", "Actions"
        };

        tableModel = new DefaultTableModel(columns, 0) {
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        resultsTable = new JTable(tableModel);
        resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        resultsTable.setRowHeight(32);
        resultsTable.setFont(new Font("SansSerif", Font.PLAIN, 12));
        resultsTable.getTableHeader().setFont(
                new Font("SansSerif", Font.BOLD, 12));
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.setGridColor(new Color(220, 220, 220));

        // Column widths
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(30);
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(110);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(200);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(90);
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(120);
        resultsTable.getColumnModel().getColumn(5).setPreferredWidth(70);
        resultsTable.getColumnModel().getColumn(6).setPreferredWidth(270);

        // XSS Type column renderer
        resultsTable.getColumnModel().getColumn(4)
                .setCellRenderer((table, value, isSelected,
                                  hasFocus, row, column) -> {
                    JLabel label = new JLabel(
                            value != null ? value.toString() : "");
                    label.setOpaque(true);
                    label.setHorizontalAlignment(SwingConstants.CENTER);
                    label.setFont(new Font("SansSerif", Font.BOLD, 11));
                    String val = value != null ? value.toString() : "";
                    switch (val) {
                        case "Reflected XSS":
                            label.setBackground(new Color(220, 80, 0));
                            label.setForeground(Color.WHITE);
                            break;
                        case "Stored XSS":
                            label.setBackground(new Color(150, 0, 0));
                            label.setForeground(Color.WHITE);
                            break;
                        case "DOM-Based XSS":
                            label.setBackground(new Color(0, 100, 180));
                            label.setForeground(Color.WHITE);
                            break;
                        default:
                            label.setBackground(new Color(80, 80, 80));
                            label.setForeground(Color.WHITE);
                            break;
                    }
                    if (isSelected) label.setOpaque(true);
                    return label;
                });

        // Severity column renderer
        resultsTable.getColumnModel().getColumn(5)
                .setCellRenderer((table, value, isSelected,
                                  hasFocus, row, column) -> {
                    JLabel label = new JLabel(
                            value != null ? value.toString() : "");
                    label.setOpaque(true);
                    label.setHorizontalAlignment(SwingConstants.CENTER);
                    label.setFont(new Font("SansSerif", Font.BOLD, 11));
                    String sev = value != null ? value.toString() : "";
                    switch (sev) {
                        case "Critical":
                            label.setBackground(new Color(180, 0, 0));
                            label.setForeground(Color.WHITE);
                            break;
                        case "High":
                            label.setBackground(new Color(220, 80, 0));
                            label.setForeground(Color.WHITE);
                            break;
                        case "Medium":
                            label.setBackground(new Color(200, 140, 0));
                            label.setForeground(Color.WHITE);
                            break;
                        default:
                            label.setBackground(new Color(80, 80, 180));
                            label.setForeground(Color.WHITE);
                            break;
                    }
                    return label;
                });

        // Actions column renderer
        resultsTable.getColumnModel().getColumn(6)
                .setCellRenderer(new ActionButtonRenderer());

        // Actions column click handler
        resultsTable.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                int row = resultsTable.rowAtPoint(e.getPoint());
                int col = resultsTable.columnAtPoint(e.getPoint());
                if (row < 0 || col != 6) return;

                int modelRow = resultsTable.convertRowIndexToModel(row);
                if (modelRow >= resultData.size()) return;

                XssFuzzer.FuzzResult result = resultData.get(modelRow);

                // Calculate which button was clicked
                Rectangle cellRect = resultsTable.getCellRect(row, col, false);
                int xInCell = e.getX() - cellRect.x;

                if (xInCell >= 5 && xInCell < 120) {
                    sendToRepeater(result);
                } else if (xInCell >= 125 && xInCell < 200) {
                    showVerifyPopup(result);
                } else if (xInCell >= 205) {
                    showRemediation(result);
                }
            }
        });

        TableRowSorter<DefaultTableModel> sorter =
                new TableRowSorter<>(tableModel);
        resultsTable.setRowSorter(sorter);

        JScrollPane scrollPane = new JScrollPane(resultsTable);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());

        // ── Status Bar ───────────────────────────────────────
        JPanel statusPanel = new JPanel(new BorderLayout());
        statusPanel.setBackground(new Color(245, 245, 245));
        statusPanel.setBorder(
                BorderFactory.createEmptyBorder(5, 15, 5, 15));

        statusLabel = new JLabel(
                "Ready — Enter URL, choose Quick Scan or Auth Scan");
        statusLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        statusLabel.setForeground(new Color(100, 100, 100));

        JButton clearButton = new JButton("Clear Results");
        clearButton.setFont(new Font("SansSerif", Font.PLAIN, 11));
        clearButton.addActionListener(e -> clearResults());

        statusPanel.add(statusLabel, BorderLayout.WEST);
        statusPanel.add(clearButton, BorderLayout.EAST);

        // ── Assemble ─────────────────────────────────────────
        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(scrollPane, BorderLayout.CENTER);
        mainPanel.add(statusPanel, BorderLayout.SOUTH);
    }

    // ── Action Button Renderer ────────────────────────────────
    private static class ActionButtonRenderer
            implements TableCellRenderer {
        public Component getTableCellRendererComponent(
                JTable table, Object value, boolean isSelected,
                boolean hasFocus, int row, int column) {
            JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
            p.setBackground(isSelected
                    ? table.getSelectionBackground() : Color.WHITE);

            JButton r = new JButton("Send to Repeater");
            r.setFont(new Font("SansSerif", Font.PLAIN, 10));
            r.setBackground(new Color(0, 102, 204));
            r.setForeground(Color.WHITE);
            r.setOpaque(true);
            r.setBorderPainted(false);
            r.setPreferredSize(new Dimension(115, 22));

            JButton v = new JButton("Copy URL");
            v.setFont(new Font("SansSerif", Font.PLAIN, 10));
            v.setBackground(new Color(0, 153, 76));
            v.setForeground(Color.WHITE);
            v.setOpaque(true);
            v.setBorderPainted(false);
            v.setPreferredSize(new Dimension(75, 22));

            JButton m = new JButton("Remediation");
            m.setFont(new Font("SansSerif", Font.PLAIN, 10));
            m.setBackground(new Color(120, 0, 120));
            m.setForeground(Color.WHITE);
            m.setOpaque(true);
            m.setBorderPainted(false);
            m.setPreferredSize(new Dimension(90, 22));

            p.add(r);
            p.add(v);
            p.add(m);
            return p;
        }
    }

    private void sendToRepeater(XssFuzzer.FuzzResult result) {
        try {
            if (api == null) return;
            String url = buildVerifyUrl(
                    result.getUrl(),
                    result.getParameter(),
                    result.getPayload());
            HttpRequest request = HttpRequest.httpRequestFromUrl(url);
            api.repeater().sendToRepeater(request,
                    "XSS: " + result.getParameter()
                            + " [" + result.getSeverity() + "]");
            setStatus("Sent to Repeater — check Repeater tab!");
            JOptionPane.showMessageDialog(mainPanel,
                    "<html><b>Sent to Burp Repeater!</b><br><br>"
                            + "Go to the <b>Repeater</b> tab<br>"
                            + "and click <b>Send</b> to verify the XSS.<br><br>"
                            + "<font color='gray'>Parameter: "
                            + result.getParameter() + "</font></html>",
                    "Sent to Repeater",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(mainPanel,
                    "Repeater error: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void showVerifyPopup(XssFuzzer.FuzzResult result) {
        String verifyUrl = buildVerifyUrl(
                result.getUrl(),
                result.getParameter(),
                result.getPayload());
        copyToClipboard(verifyUrl);
        JOptionPane.showMessageDialog(mainPanel,
                "<html>"
                        + "<b style='font-size:13px'>XSS Vulnerability Found!</b>"
                        + "<br><br>"
                        + "<b>Location:</b> " + result.getLocation() + "<br>"
                        + "<b>URL:</b> " + result.getUrl() + "<br>"
                        + "<b>Parameter:</b> " + result.getParameter() + "<br>"
                        + "<b>XSS Type:</b> " + result.getType() + "<br>"
                        + "<b>Severity:</b> " + result.getSeverity() + "<br><br>"
                        + "<b>Verify URL (copied!):</b><br>"
                        + "<font color='blue'>" + verifyUrl + "</font><br><br>"
                        + "<b>Steps to verify:</b><br>"
                        + "1. Paste URL in browser<br>"
                        + "2. Look for alert popup: 'XSS-Sentinel'<br>"
                        + "3. Alert appears = Confirmed vulnerability!<br><br>"
                        + "<font color='gray'>Tip: Use 'Send to Repeater' "
                        + "to verify inside Burp</font>"
                        + "</html>",
                "Verify XSS Finding",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void showRemediation(XssFuzzer.FuzzResult result) {
        JTextArea textArea = new JTextArea(result.getRemediation());
        textArea.setEditable(false);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setBackground(new Color(245, 245, 245));
        textArea.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JScrollPane scroll = new JScrollPane(textArea);
        scroll.setPreferredSize(new Dimension(580, 380));

        JPanel panel = new JPanel(new BorderLayout(0, 10));
        JLabel header = new JLabel(
                "<html><b>Remediation Guide</b>"
                        + " — Parameter: <font color='red'>"
                        + result.getParameter()
                        + "</font> | Type: <font color='orange'>"
                        + result.getType()
                        + "</font> | Severity: <font color='darkred'>"
                        + result.getSeverity()
                        + "</font></html>");
        header.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
        panel.add(header, BorderLayout.NORTH);
        panel.add(scroll, BorderLayout.CENTER);

        JOptionPane.showMessageDialog(mainPanel,
                panel,
                "XSS Remediation Guide",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void copyToClipboard(String text) {
        try {
            StringSelection sel = new StringSelection(text);
            Toolkit.getDefaultToolkit()
                    .getSystemClipboard()
                    .setContents(sel, null);
        } catch (Exception e) {
            System.err.println("Clipboard error: " + e.getMessage());
        }
    }

    private boolean validateUrl(String url) {
        if (url.isEmpty() || url.equals("http://")
                || url.equals("https://")) {
            JOptionPane.showMessageDialog(mainPanel,
                    "Please enter a target URL first!",
                    "No URL", JOptionPane.WARNING_MESSAGE);
            return false;
        }
        return true;
    }

    private JLabel makeLabel(String text) {
        JLabel label = new JLabel(text);
        label.setForeground(new Color(200, 200, 200));
        label.setFont(new Font("SansSerif", Font.PLAIN, 11));
        return label;
    }

    private void styleTextField(JComponent field) {
        field.setBackground(new Color(70, 70, 70));
        if (field instanceof JTextField) {
            ((JTextField) field).setForeground(Color.WHITE);
            ((JTextField) field).setCaretColor(Color.WHITE);
        }
        if (field instanceof JPasswordField) {
            ((JPasswordField) field).setForeground(Color.WHITE);
            ((JPasswordField) field).setCaretColor(Color.WHITE);
        }
        field.setBorder(BorderFactory.createEmptyBorder(3, 6, 3, 6));
    }

    public void setCrawlCallback(
            BiConsumer<String, LoginCredentials> callback) {
        this.crawlCallback = callback;
    }

    public void addResult(XssFuzzer.FuzzResult result) {
        SwingUtilities.invokeLater(() -> {
            totalVulnerable++;
            resultData.add(result);

            String xssType = formatXssType(result.getType());

            tableModel.addRow(new Object[]{
                    totalVulnerable,
                    result.getLocation(),
                    result.getUrl(),
                    result.getParameter(),
                    xssType,
                    result.getSeverity(),
                    "actions"
            });
            updateStats();
            statusLabel.setText("Found: "
                    + result.getParameter()
                    + " in " + result.getLocation()
                    + " [" + result.getSeverity() + "]");
        });
    }

    private String formatXssType(
            com.xsssentinel.analyzer.XssAnalyzer.VulnerabilityType type) {
        switch (type) {
            case REFLECTED: return "Reflected XSS";
            case STORED:    return "Stored XSS";
            case DOM_BASED: return "DOM-Based XSS";
            default:        return "Reflected XSS";
        }
    }

    public void addResults(List<XssFuzzer.FuzzResult> results) {
        for (XssFuzzer.FuzzResult result : results) {
            if (result.isVulnerable()) {
                addResult(result);
            }
        }
    }

    public void incrementScanned() {
        SwingUtilities.invokeLater(() -> {
            totalScanned++;
            updateStats();
        });
    }

    public void setStatus(String message) {
        SwingUtilities.invokeLater(() ->
                statusLabel.setText(message));
    }

    private void updateStats() {
        statsLabel.setText("Scanned: " + totalScanned
                + " | Vulnerable: " + totalVulnerable);
    }

    private String buildVerifyUrl(String url,
                                  String parameter, String payload) {
        String baseUrl = url.contains("?")
                ? url.substring(0, url.indexOf("?")) : url;
        return baseUrl + "?" + parameter + "=" + payload;
    }

    private void clearResults() {
        tableModel.setRowCount(0);
        resultData.clear();
        totalScanned = 0;
        totalVulnerable = 0;
        updateStats();
        statusLabel.setText("Results cleared — Ready");
    }

    private String shortenUrl(String url) {
        if (url == null) return "";
        if (url.length() > 40) return url.substring(0, 40) + "...";
        return url;
    }

    public JPanel getPanel() {
        return mainPanel;
    }
}