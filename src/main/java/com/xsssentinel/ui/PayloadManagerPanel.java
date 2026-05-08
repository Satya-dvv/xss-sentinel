package com.xsssentinel.ui;

import com.xsssentinel.payloads.PayloadManager;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.*;
import java.util.List;

public class PayloadManagerPanel {

    private final JPanel mainPanel;
    private final DefaultListModel<String> builtInModel;
    private final DefaultListModel<String> customModel;
    private final PayloadManager payloadManager;
    private final JTextField payloadInputField;
    private JLabel customCountLabel;
    private JLabel totalCountLabel;

    public PayloadManagerPanel(PayloadManager payloadManager) {
        this.payloadManager = payloadManager;
        this.builtInModel = new DefaultListModel<>();
        this.customModel = new DefaultListModel<>();

        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBackground(Color.WHITE);

        // ── Header ──────────────────────────────────────────
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(new Color(35, 35, 35));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(
                10, 15, 10, 15));

        JLabel titleLabel = new JLabel(
                "XSS-Sentinel - Payload Manager");
        titleLabel.setForeground(Color.WHITE);
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 16));

        totalCountLabel = new JLabel("Total Payloads: 0");
        totalCountLabel.setForeground(new Color(180, 180, 180));
        totalCountLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));

        headerPanel.add(titleLabel, BorderLayout.WEST);
        headerPanel.add(totalCountLabel, BorderLayout.EAST);

        // ── Main Content ─────────────────────────────────────
        JPanel contentPanel = new JPanel(new GridLayout(1, 2, 10, 0));
        contentPanel.setBackground(Color.WHITE);
        contentPanel.setBorder(BorderFactory.createEmptyBorder(
                10, 10, 10, 10));

        // ── Left Panel — Built-in Payloads ───────────────────
        JPanel builtInPanel = new JPanel(new BorderLayout(0, 5));
        builtInPanel.setBackground(Color.WHITE);

        TitledBorder builtInBorder = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(200, 200, 200)),
                "Built-in Payloads (Read Only)");
        builtInBorder.setTitleFont(new Font("SansSerif", Font.BOLD, 12));
        builtInPanel.setBorder(builtInBorder);

        JList<String> builtInList = new JList<>(builtInModel);
        builtInList.setFont(new Font("Monospaced", Font.PLAIN, 11));
        builtInList.setSelectionMode(
                ListSelectionModel.SINGLE_SELECTION);
        builtInList.setBackground(new Color(248, 248, 248));

        JScrollPane builtInScroll = new JScrollPane(builtInList);
        builtInScroll.setBorder(BorderFactory.createEmptyBorder());

        // Category filter buttons
        JPanel categoryPanel = new JPanel(
                new FlowLayout(FlowLayout.LEFT, 5, 5));
        categoryPanel.setBackground(Color.WHITE);

        JButton allBtn = makeCategoryButton(
                "All", new Color(60, 60, 60));
        JButton basicBtn = makeCategoryButton(
                "Basic", new Color(0, 120, 0));
        JButton bypassBtn = makeCategoryButton(
                "Bypass", new Color(180, 60, 0));
        JButton domBtn = makeCategoryButton(
                "DOM", new Color(0, 80, 180));
        JButton polyBtn = makeCategoryButton(
                "Polyglot", new Color(120, 0, 120));

        allBtn.addActionListener(e -> loadBuiltInPayloads());
        basicBtn.addActionListener(e -> loadCategory("Basic"));
        bypassBtn.addActionListener(e -> loadCategory("Bypass"));
        domBtn.addActionListener(e -> loadCategory("DOM"));
        polyBtn.addActionListener(e -> loadCategory("Polyglot"));

        categoryPanel.add(allBtn);
        categoryPanel.add(basicBtn);
        categoryPanel.add(bypassBtn);
        categoryPanel.add(domBtn);
        categoryPanel.add(polyBtn);

        JButton copySelectedBtn = new JButton("Copy Selected");
        copySelectedBtn.setFont(new Font("SansSerif", Font.PLAIN, 11));
        copySelectedBtn.addActionListener(e -> {
            String selected = builtInList.getSelectedValue();
            if (selected != null) {
                copyToClipboard(selected);
                JOptionPane.showMessageDialog(mainPanel,
                        "Payload copied to clipboard!",
                        "Copied",
                        JOptionPane.INFORMATION_MESSAGE);
            }
        });

        JPanel builtInBottom = new JPanel(new BorderLayout());
        builtInBottom.setBackground(Color.WHITE);
        builtInBottom.add(categoryPanel, BorderLayout.CENTER);
        builtInBottom.add(copySelectedBtn, BorderLayout.EAST);

        builtInPanel.add(builtInScroll, BorderLayout.CENTER);
        builtInPanel.add(builtInBottom, BorderLayout.SOUTH);

        // ── Right Panel — Custom Payloads ────────────────────
        JPanel customPanel = new JPanel(new BorderLayout(0, 5));
        customPanel.setBackground(Color.WHITE);

        TitledBorder customBorder = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(255, 102, 0)),
                "Custom Payloads (Editable)");
        customBorder.setTitleFont(new Font("SansSerif", Font.BOLD, 12));
        customBorder.setTitleColor(new Color(255, 102, 0));
        customPanel.setBorder(customBorder);

        JList<String> customList = new JList<>(customModel);
        customList.setFont(new Font("Monospaced", Font.PLAIN, 11));
        customList.setSelectionMode(
                ListSelectionModel.SINGLE_SELECTION);
        customList.setBackground(new Color(255, 252, 245));

        JScrollPane customScroll = new JScrollPane(customList);
        customScroll.setBorder(BorderFactory.createEmptyBorder());

        // Add payload input
        JPanel addPanel = new JPanel(new BorderLayout(5, 0));
        addPanel.setBackground(Color.WHITE);
        addPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));

        payloadInputField = new JTextField();
        payloadInputField.setFont(new Font("Monospaced", Font.PLAIN, 12));
        payloadInputField.setToolTipText(
                "Enter your custom XSS payload here");
        payloadInputField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(200, 200, 200)),
                BorderFactory.createEmptyBorder(4, 6, 4, 6)));

        JButton addBtn = new JButton("Add");
        addBtn.setFont(new Font("SansSerif", Font.BOLD, 12));
        addBtn.setBackground(new Color(0, 153, 76));
        addBtn.setForeground(Color.WHITE);
        addBtn.setOpaque(true);
        addBtn.setBorderPainted(false);
        addBtn.setPreferredSize(new Dimension(60, 30));

        addBtn.addActionListener(e -> {
            String payload = payloadInputField.getText().trim();
            if (payload.isEmpty()) {
                JOptionPane.showMessageDialog(mainPanel,
                        "Please enter a payload first!",
                        "Empty Payload",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
            payloadManager.addCustomPayload(payload);
            customModel.addElement(payload);
            payloadInputField.setText("");
            updateCounts();
            JOptionPane.showMessageDialog(mainPanel,
                    "Custom payload added!\n"
                            + "It will be used in the next scan.",
                    "Payload Added",
                    JOptionPane.INFORMATION_MESSAGE);
        });

        payloadInputField.addActionListener(e -> addBtn.doClick());

        addPanel.add(payloadInputField, BorderLayout.CENTER);
        addPanel.add(addBtn, BorderLayout.EAST);

        // Action buttons
        JPanel actionPanel = new JPanel(
                new FlowLayout(FlowLayout.LEFT, 5, 5));
        actionPanel.setBackground(Color.WHITE);

        JButton removeBtn = new JButton("Remove Selected");
        removeBtn.setFont(new Font("SansSerif", Font.PLAIN, 11));
        removeBtn.setBackground(new Color(180, 0, 0));
        removeBtn.setForeground(Color.WHITE);
        removeBtn.setOpaque(true);
        removeBtn.setBorderPainted(false);
        removeBtn.addActionListener(e -> {
            int index = customList.getSelectedIndex();
            if (index == -1) {
                JOptionPane.showMessageDialog(mainPanel,
                        "Please select a payload to remove!",
                        "Nothing Selected",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
            String payload = customModel.getElementAt(index);
            payloadManager.removeCustomPayload(payload);
            customModel.removeElementAt(index);
            updateCounts();
        });

        JButton clearAllBtn = new JButton("Clear All");
        clearAllBtn.setFont(new Font("SansSerif", Font.PLAIN, 11));
        clearAllBtn.setBackground(new Color(100, 100, 100));
        clearAllBtn.setForeground(Color.WHITE);
        clearAllBtn.setOpaque(true);
        clearAllBtn.setBorderPainted(false);
        clearAllBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(mainPanel,
                    "Clear all custom payloads?",
                    "Confirm Clear", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                payloadManager.clearCustomPayloads();
                customModel.clear();
                updateCounts();
            }
        });

        JButton importBtn = new JButton("Import .txt");
        importBtn.setFont(new Font("SansSerif", Font.PLAIN, 11));
        importBtn.setBackground(new Color(0, 102, 204));
        importBtn.setForeground(Color.WHITE);
        importBtn.setOpaque(true);
        importBtn.setBorderPainted(false);
        importBtn.addActionListener(e -> importPayloads());

        JButton exportBtn = new JButton("Export .txt");
        exportBtn.setFont(new Font("SansSerif", Font.PLAIN, 11));
        exportBtn.setBackground(new Color(0, 102, 204));
        exportBtn.setForeground(Color.WHITE);
        exportBtn.setOpaque(true);
        exportBtn.setBorderPainted(false);
        exportBtn.addActionListener(e -> exportPayloads());

        actionPanel.add(removeBtn);
        actionPanel.add(clearAllBtn);
        actionPanel.add(importBtn);
        actionPanel.add(exportBtn);

        customCountLabel = new JLabel("Custom: 0 payloads");
        customCountLabel.setFont(
                new Font("SansSerif", Font.ITALIC, 11));
        customCountLabel.setForeground(new Color(150, 150, 150));

        JPanel customBottom = new JPanel(new BorderLayout(0, 3));
        customBottom.setBackground(Color.WHITE);
        customBottom.add(addPanel, BorderLayout.NORTH);
        customBottom.add(actionPanel, BorderLayout.CENTER);
        customBottom.add(customCountLabel, BorderLayout.SOUTH);

        customPanel.add(customScroll, BorderLayout.CENTER);
        customPanel.add(customBottom, BorderLayout.SOUTH);

        contentPanel.add(builtInPanel);
        contentPanel.add(customPanel);

        // ── Info Bar ─────────────────────────────────────────
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBackground(new Color(245, 245, 245));
        infoPanel.setBorder(
                BorderFactory.createEmptyBorder(5, 15, 5, 15));

        JLabel infoLabel = new JLabel(
                "Custom payloads are automatically included in all "
                        + "scans. Import from .txt file (one payload per line).");
        infoLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        infoLabel.setForeground(new Color(100, 100, 100));

        infoPanel.add(infoLabel, BorderLayout.WEST);

        // ── Assemble ─────────────────────────────────────────
        mainPanel.add(headerPanel, BorderLayout.NORTH);
        mainPanel.add(contentPanel, BorderLayout.CENTER);
        mainPanel.add(infoPanel, BorderLayout.SOUTH);

        // Load payloads AFTER all labels are initialized
        loadBuiltInPayloads();
        updateCounts();
    }

    private void loadBuiltInPayloads() {
        builtInModel.clear();
        List<String> all = payloadManager.getAllBuiltInPayloads();
        for (String p : all) {
            builtInModel.addElement(p);
        }
        updateCounts();
    }

    private void loadCategory(String category) {
        builtInModel.clear();
        List<String> payloads;
        switch (category) {
            case "Basic":
                payloads = payloadManager.getBasicPayloads();
                break;
            case "Bypass":
                payloads = payloadManager.getBypassPayloads();
                break;
            case "DOM":
                payloads = payloadManager.getDomPayloads();
                break;
            case "Polyglot":
                payloads = payloadManager.getPolyglotPayloads();
                break;
            default:
                payloads = payloadManager.getAllBuiltInPayloads();
                break;
        }
        for (String p : payloads) {
            builtInModel.addElement(p);
        }
    }

    private JButton makeCategoryButton(String text, Color color) {
        JButton btn = new JButton(text);
        btn.setFont(new Font("SansSerif", Font.PLAIN, 11));
        btn.setBackground(color);
        btn.setForeground(Color.WHITE);
        btn.setOpaque(true);
        btn.setBorderPainted(false);
        btn.setPreferredSize(new Dimension(70, 24));
        return btn;
    }

    private void importPayloads() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Import Payloads from .txt file");
        fileChooser.setFileFilter(
                new javax.swing.filechooser.FileNameExtensionFilter(
                        "Text files", "txt"));

        int result = fileChooser.showOpenDialog(mainPanel);
        if (result != JFileChooser.APPROVE_OPTION) return;

        File file = fileChooser.getSelectedFile();
        int count = 0;

        try (BufferedReader reader = new BufferedReader(
                new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    payloadManager.addCustomPayload(line);
                    customModel.addElement(line);
                    count++;
                }
            }
            updateCounts();
            JOptionPane.showMessageDialog(mainPanel,
                    count + " payloads imported successfully!",
                    "Import Complete",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(mainPanel,
                    "Error importing file: " + e.getMessage(),
                    "Import Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportPayloads() {
        if (customModel.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel,
                    "No custom payloads to export!",
                    "Nothing to Export",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Custom Payloads");
        fileChooser.setSelectedFile(new File("custom-payloads.txt"));

        int result = fileChooser.showSaveDialog(mainPanel);
        if (result != JFileChooser.APPROVE_OPTION) return;

        File file = fileChooser.getSelectedFile();

        try (PrintWriter writer = new PrintWriter(
                new FileWriter(file))) {
            writer.println("# XSS-Sentinel Custom Payloads");
            writer.println("# Exported on: " + new java.util.Date());
            writer.println();
            for (int i = 0; i < customModel.size(); i++) {
                writer.println(customModel.getElementAt(i));
            }
            JOptionPane.showMessageDialog(mainPanel,
                    "Payloads exported to: " + file.getName(),
                    "Export Complete",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(mainPanel,
                    "Error exporting: " + e.getMessage(),
                    "Export Error", JOptionPane.ERROR_MESSAGE);
        }
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

    private void updateCounts() {
        if (totalCountLabel == null || customCountLabel == null) return;
        int builtIn = payloadManager.getAllBuiltInPayloads().size();
        int custom = payloadManager.getCustomPayloads().size();
        int total = builtIn + custom;
        totalCountLabel.setText("Total Payloads: " + total);
        customCountLabel.setText("Custom: " + custom + " payloads");
    }

    public JPanel getPanel() {
        return mainPanel;
    }
}