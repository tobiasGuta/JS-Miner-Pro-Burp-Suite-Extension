package com.burp.custom.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.burp.custom.JsMinerExtension;
import com.burp.custom.model.Finding;
import com.burp.custom.util.EntropyAnalyzer;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Type;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

public class ResultsTab extends JPanel {

    private final MontoyaApi api;
    private final JsMinerExtension extension;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final Gson gson;

    // Use the new Finding model and a Set for deduplication
    private final List<Finding> findingsList = new ArrayList<>();
    private final Set<String> uniqueFindingKeys = new HashSet<>();
    
    // Track duplicate secrets across URLs (secret -> list of URLs)
    private final Map<String, Set<String>> secretToUrls = new HashMap<>();

    private static final String FINDINGS_KEY = "jsminer_findings";

    // Severity filter
    private JComboBox<String> severityFilter;
    private JComboBox<String> typeFilter;
    private JComboBox<String> entropyFilter;
    private JTextField searchField;
    private JLabel statsLabel;

    public ResultsTab(MontoyaApi api, JsMinerExtension extension) {
        this.api = api;
        this.extension = extension;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        this.setLayout(new BorderLayout());

        // 1. Top Half: The Findings Table with new columns
        String[] columns = {"Severity", "Type", "Finding", "Rule Name", "Entropy", "Reuse", "Source URL"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);
        
        // Set column widths
        table.getColumnModel().getColumn(0).setPreferredWidth(60);  // Severity
        table.getColumnModel().getColumn(1).setPreferredWidth(60);  // Type
        table.getColumnModel().getColumn(2).setPreferredWidth(300); // Finding
        table.getColumnModel().getColumn(3).setPreferredWidth(120); // Rule Name
        table.getColumnModel().getColumn(4).setPreferredWidth(50);  // Entropy
        table.getColumnModel().getColumn(5).setPreferredWidth(40);  // Reuse
        table.getColumnModel().getColumn(6).setPreferredWidth(250); // URL
        
        // Custom renderer for entropy column (color-coded)
        table.getColumnModel().getColumn(4).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                String entropy = (String) value;
                if (!isSelected) {
                    if ("VERY HIGH".equals(entropy)) {
                        c.setBackground(new Color(255, 100, 100));
                        c.setForeground(Color.WHITE);
                    } else if ("HIGH".equals(entropy)) {
                        c.setBackground(new Color(255, 180, 100));
                    } else if ("MEDIUM".equals(entropy)) {
                        c.setBackground(new Color(255, 255, 150));
                    } else {
                        c.setBackground(Color.WHITE);
                    }
                }
                return c;
            }
        });
        
        // Custom renderer for reuse column (highlight duplicates)
        table.getColumnModel().getColumn(5).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (!isSelected) {
                    int reuse = 1;
                    try {
                        reuse = Integer.parseInt((String) value);
                    } catch (Exception e) {}
                    if (reuse > 5) {
                        c.setBackground(new Color(255, 50, 50));
                        c.setForeground(Color.WHITE);
                    } else if (reuse > 2) {
                        c.setBackground(new Color(255, 150, 50));
                    } else if (reuse > 1) {
                        c.setBackground(new Color(255, 220, 100));
                    } else {
                        c.setBackground(Color.WHITE);
                    }
                }
                setHorizontalAlignment(SwingConstants.CENTER);
                return c;
            }
        });
        
        // Custom sorter for severity column
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
        sorter.setComparator(0, (s1, s2) -> {
            int order1 = getSeverityOrder((String) s1);
            int order2 = getSeverityOrder((String) s2);
            return Integer.compare(order2, order1); // Descending (HIGH first)
        });
        // Sort entropy column
        sorter.setComparator(4, (s1, s2) -> {
            int order1 = getEntropyOrder((String) s1);
            int order2 = getEntropyOrder((String) s2);
            return Integer.compare(order2, order1);
        });
        // Sort reuse column numerically
        sorter.setComparator(5, (s1, s2) -> {
            int v1 = 1, v2 = 1;
            try { v1 = Integer.parseInt((String) s1); } catch (Exception e) {}
            try { v2 = Integer.parseInt((String) s2); } catch (Exception e) {}
            return Integer.compare(v2, v1);
        });
        table.setRowSorter(sorter);
        
        JScrollPane tableScroll = new JScrollPane(table);

        // 2. Bottom Half: The Editors
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        JSplitPane editorsSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestEditor.uiComponent(), responseEditor.uiComponent());
        editorsSplitPane.setResizeWeight(0.5);

        // 3. Main Split Pane
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, editorsSplitPane);
        mainSplitPane.setResizeWeight(0.5);

        // 4. Control Panel with filters
        JPanel controlPanel = new JPanel(new BorderLayout());
        
        // Filter panel
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        filterPanel.add(new JLabel("Severity:"));
        severityFilter = new JComboBox<>(new String[]{"All", "HIGH", "MEDIUM", "LOW", "INFO"});
        severityFilter.addActionListener(e -> applyFilters());
        filterPanel.add(severityFilter);
        
        filterPanel.add(Box.createHorizontalStrut(10));
        filterPanel.add(new JLabel("Type:"));
        typeFilter = new JComboBox<>(new String[]{"All", "SECRET", "URL", "ENDPOINT", "FILE", "INFO"});
        typeFilter.addActionListener(e -> applyFilters());
        filterPanel.add(typeFilter);
        
        filterPanel.add(Box.createHorizontalStrut(10));
        filterPanel.add(new JLabel("Search:"));
        searchField = new JTextField(20);
        searchField.addActionListener(e -> applyFilters());
        filterPanel.add(searchField);
        
        JButton filterButton = new JButton("Filter");
        filterButton.addActionListener(e -> applyFilters());
        filterPanel.add(filterButton);
        
        controlPanel.add(filterPanel, BorderLayout.NORTH);
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton scanHistoryButton = new JButton("Scan Proxy History");
        JButton clearButton = new JButton("Clear Results");
        JButton saveButton = new JButton("Save Results");
        JButton exportJsonButton = new JButton("Export JSON");
        JButton exportCsvButton = new JButton("Export CSV");
        
        scanHistoryButton.setBackground(new Color(70, 130, 180));
        scanHistoryButton.setForeground(Color.WHITE);
        scanHistoryButton.setToolTipText("Scan all items in Proxy HTTP History for secrets and endpoints");
        scanHistoryButton.addActionListener(e -> {
            scanHistoryButton.setEnabled(false);
            scanHistoryButton.setText("Scanning...");
            extension.scanProxyHistory();
            // Re-enable after a short delay (the actual scan runs async)
            new javax.swing.Timer(2000, evt -> {
                scanHistoryButton.setEnabled(true);
                scanHistoryButton.setText("Scan Proxy History");
                ((javax.swing.Timer) evt.getSource()).stop();
            }).start();
        });
        
        clearButton.addActionListener(e -> clearResults());
        saveButton.addActionListener(e -> {
            saveFindings();
            JOptionPane.showMessageDialog(this, "Results saved to project file.", "Saved", JOptionPane.INFORMATION_MESSAGE);
        });
        exportJsonButton.addActionListener(e -> exportFindings("json"));
        exportCsvButton.addActionListener(e -> exportFindings("csv"));
        
        buttonPanel.add(scanHistoryButton);
        buttonPanel.add(Box.createHorizontalStrut(15));
        buttonPanel.add(clearButton);
        buttonPanel.add(saveButton);
        buttonPanel.add(exportJsonButton);
        buttonPanel.add(exportCsvButton);
        
        controlPanel.add(buttonPanel, BorderLayout.SOUTH);

        this.add(controlPanel, BorderLayout.NORTH);
        this.add(mainSplitPane, BorderLayout.CENTER);

        // 5. Selection Listener
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = table.getSelectedRow();
                if (viewRow != -1) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    if (modelRow >= 0 && modelRow < findingsList.size()) {
                        Finding finding = findingsList.get(modelRow);
                        displayFinding(finding);
                    }
                }
            }
        });

        // 6. Context Menu
        setupContextMenu();

        // Load findings on startup
        loadFindings();
    }

    private void setupContextMenu() {
        JPopupMenu contextMenu = new JPopupMenu();
        
        JMenuItem copyFinding = new JMenuItem("Copy Finding");
        copyFinding.addActionListener(e -> copySelectedFinding());
        contextMenu.add(copyFinding);
        
        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> copySelectedUrl());
        contextMenu.add(copyUrl);
        
        contextMenu.addSeparator();
        
        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> sendSelectedToRepeater());
        contextMenu.add(sendToRepeater);
        
        JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");
        sendToIntruder.addActionListener(e -> sendSelectedToIntruder());
        contextMenu.add(sendToIntruder);
        
        JMenuItem sendToOrganizer = new JMenuItem("Send to Organizer");
        sendToOrganizer.addActionListener(e -> sendSelectedToOrganizer());
        contextMenu.add(sendToOrganizer);
        
        contextMenu.addSeparator();
        
        JMenuItem deleteRow = new JMenuItem("Delete Finding");
        deleteRow.addActionListener(e -> deleteSelectedFinding());
        contextMenu.add(deleteRow);

        table.setComponentPopupMenu(contextMenu);
    }

    private Finding getSelectedFinding() {
        int viewRow = table.getSelectedRow();
        if (viewRow == -1) return null;
        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow >= 0 && modelRow < findingsList.size()) {
            return findingsList.get(modelRow);
        }
        return null;
    }

    private void copySelectedFinding() {
        Finding finding = getSelectedFinding();
        if (finding != null) {
            StringSelection selection = new StringSelection(finding.getFinding());
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
        }
    }

    private void copySelectedUrl() {
        Finding finding = getSelectedFinding();
        if (finding != null) {
            StringSelection selection = new StringSelection(finding.getUrl());
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
        }
    }

    private void sendSelectedToRepeater() {
        Finding finding = getSelectedFinding();
        if (finding != null && finding.getRequestResponse() != null) {
            api.repeater().sendToRepeater(finding.getRequestResponse().request(), "JS Miner: " + finding.getRuleName());
        } else if (finding != null && finding.getRequestString() != null) {
            api.repeater().sendToRepeater(HttpRequest.httpRequest(finding.getRequestString()), "JS Miner: " + finding.getRuleName());
        }
    }

    private void sendSelectedToIntruder() {
        Finding finding = getSelectedFinding();
        if (finding != null && finding.getRequestResponse() != null) {
            api.intruder().sendToIntruder(finding.getRequestResponse().request());
        } else if (finding != null && finding.getRequestString() != null) {
            api.intruder().sendToIntruder(HttpRequest.httpRequest(finding.getRequestString()));
        }
    }

    private void sendSelectedToOrganizer() {
        Finding finding = getSelectedFinding();
        if (finding != null && finding.getRequestResponse() != null) {
            api.organizer().sendToOrganizer(finding.getRequestResponse());
        } else if (finding != null && finding.getRequestString() != null && finding.getResponseString() != null) {
            HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequest(finding.getRequestString()),
                HttpResponse.httpResponse(finding.getResponseString())
            );
            api.organizer().sendToOrganizer(reqResp);
        }
    }

    private void deleteSelectedFinding() {
        int viewRow = table.getSelectedRow();
        if (viewRow == -1) return;
        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow >= 0 && modelRow < findingsList.size()) {
            Finding finding = findingsList.get(modelRow);
            uniqueFindingKeys.remove(finding.getUniqueKey());
            findingsList.remove(modelRow);
            tableModel.removeRow(modelRow);
        }
    }

    private void displayFinding(Finding finding) {
        // Logic to display request/response
        // 1. Try the live object first
        if (finding.getRequestResponse() != null) {
            requestEditor.setRequest(finding.getRequestResponse().request());
            responseEditor.setResponse(finding.getRequestResponse().response());
        } 
        // 2. Fallback to the persisted strings
        else if (finding.getRequestString() != null && finding.getResponseString() != null) {
            requestEditor.setRequest(HttpRequest.httpRequest(finding.getRequestString()));
            responseEditor.setResponse(HttpResponse.httpResponse(finding.getResponseString()));
        } 
        // 3. Nothing available
        else {
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
        }

        // Highlight the finding if we have a response
        if (responseEditor.getResponse() != null) {
            responseEditor.setSearchExpression(finding.getFinding());
        }
    }

    private int getSeverityOrder(String severity) {
        switch (severity.toUpperCase()) {
            case "HIGH": return 4;
            case "MEDIUM": return 3;
            case "LOW": return 2;
            case "INFO": return 1;
            default: return 0;
        }
    }

    private int getEntropyOrder(String entropy) {
        if (entropy == null) return 0;
        switch (entropy.toUpperCase()) {
            case "VERY HIGH": return 4;
            case "HIGH": return 3;
            case "MEDIUM": return 2;
            case "LOW": return 1;
            default: return 0;
        }
    }

    private void applyFilters() {
        String severity = (String) severityFilter.getSelectedItem();
        String type = (String) typeFilter.getSelectedItem();
        String search = searchField.getText().toLowerCase();

        TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) table.getRowSorter();
        
        sorter.setRowFilter(new javax.swing.RowFilter<DefaultTableModel, Integer>() {
            @Override
            public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
                String rowSeverity = (String) entry.getValue(0);
                String rowType = (String) entry.getValue(1);
                String rowFinding = ((String) entry.getValue(2)).toLowerCase();
                String rowUrl = ((String) entry.getValue(6)).toLowerCase(); // URL is now column 6

                boolean severityMatch = "All".equals(severity) || severity.equals(rowSeverity);
                boolean typeMatch = "All".equals(type) || type.equals(rowType);
                boolean searchMatch = search.isEmpty() || rowFinding.contains(search) || rowUrl.contains(search);

                return severityMatch && typeMatch && searchMatch;
            }
        });
    }

    private void exportFindings(String format) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Findings");
        
        String extension = format.equals("json") ? "json" : "csv";
        fileChooser.setFileFilter(new FileNameExtensionFilter(extension.toUpperCase() + " files", extension));
        
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        fileChooser.setSelectedFile(new File("jsminer_findings_" + timestamp + "." + extension));
        
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            if (!file.getName().endsWith("." + extension)) {
                file = new File(file.getAbsolutePath() + "." + extension);
            }
            
            try (FileWriter writer = new FileWriter(file)) {
                if (format.equals("json")) {
                    exportToJson(writer);
                } else {
                    exportToCsv(writer);
                }
                JOptionPane.showMessageDialog(this, "Exported " + findingsList.size() + " findings to: " + file.getName(), 
                    "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage(), 
                    "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportToJson(FileWriter writer) throws IOException {
        List<Map<String, Object>> exportData = new ArrayList<>();
        for (Finding f : findingsList) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("severity", f.getSeverity());
            item.put("type", f.getType());
            item.put("finding", f.getFinding());
            item.put("ruleName", f.getRuleName());
            item.put("url", f.getUrl());
            item.put("timestamp", f.getTimestamp());
            exportData.add(item);
        }
        writer.write(gson.toJson(exportData));
    }

    private void exportToCsv(FileWriter writer) throws IOException {
        // Header
        writer.write("Severity,Type,Finding,Rule Name,URL\n");
        
        for (Finding f : findingsList) {
            writer.write(String.format("%s,%s,\"%s\",%s,\"%s\"\n",
                escapeCsv(f.getSeverity()),
                escapeCsv(f.getType()),
                escapeCsv(f.getFinding()),
                escapeCsv(f.getRuleName()),
                escapeCsv(f.getUrl())
            ));
        }
    }

    private String escapeCsv(String value) {
        if (value == null) return "";
        return value.replace("\"", "\"\"").replace("\n", " ").replace("\r", "");
    }

    public void addFinding(String type, String finding, String ruleName, String url, HttpRequestResponse reqResp, int start, int end, String severity) {
        Finding newFinding = new Finding(type, finding, ruleName, url, reqResp, start, end, severity);

        // Deduplication check
        if (uniqueFindingKeys.add(newFinding.getUniqueKey())) {
            // Calculate entropy for the finding
            EntropyAnalyzer.EntropyResult entropyResult = EntropyAnalyzer.analyze(finding);
            String entropyLevel = entropyResult.level;
            
            // Track secret reuse across URLs
            secretToUrls.computeIfAbsent(finding, k -> new java.util.HashSet<>()).add(url);
            int reuseCount = secretToUrls.get(finding).size();
            
            SwingUtilities.invokeLater(() -> {
                findingsList.add(newFinding);
                tableModel.addRow(new Object[]{severity, type, finding, ruleName, entropyLevel, String.valueOf(reuseCount), url});
                
                // Update reuse count for all rows with the same finding
                if (reuseCount > 1) {
                    updateReuseCounts(finding, reuseCount);
                }
            });
        }
    }
    
    private void updateReuseCounts(String finding, int newCount) {
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String rowFinding = (String) tableModel.getValueAt(i, 2);
            if (finding.equals(rowFinding)) {
                tableModel.setValueAt(String.valueOf(newCount), i, 5);
            }
        }
    }
    
    public void saveAllFindings() {
        saveFindings();
    }

    private void clearResults() {
        SwingUtilities.invokeLater(() -> {
            tableModel.setRowCount(0);
            findingsList.clear();
            uniqueFindingKeys.clear();
            secretToUrls.clear();
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
            // Clear from persistence
            api.persistence().extensionData().deleteString(FINDINGS_KEY);
        });
    }

    private void saveFindings() {
        try {
            PersistedObject prefs = api.persistence().extensionData();
            String json = gson.toJson(findingsList);
            prefs.setString(FINDINGS_KEY, json);
        } catch (Exception e) {
            extension.log(JsMinerExtension.LogLevel.ERROR, "Failed to save findings: " + e.getMessage());
        }
    }

    private void loadFindings() {
        try {
            PersistedObject prefs = api.persistence().extensionData();
            String json = prefs.getString(FINDINGS_KEY);
            if (json != null && !json.isEmpty()) {
                Type listType = new TypeToken<ArrayList<Finding>>(){}.getType();
                List<Finding> loadedFindings = gson.fromJson(json, listType);

                if (loadedFindings != null) {
                    for (Finding finding : loadedFindings) {
                        // Add to UI and internal state without re-saving
                        if (uniqueFindingKeys.add(finding.getUniqueKey())) {
                            findingsList.add(finding);
                            
                            // Calculate entropy for loaded finding
                            EntropyAnalyzer.EntropyResult entropyResult = EntropyAnalyzer.analyze(finding.getFinding());
                            String entropyLevel = entropyResult.level;
                            
                            // Track secret reuse
                            secretToUrls.computeIfAbsent(finding.getFinding(), k -> new java.util.HashSet<>()).add(finding.getUrl());
                            int reuseCount = secretToUrls.get(finding.getFinding()).size();
                            
                            tableModel.addRow(new Object[]{
                                finding.getSeverity(), 
                                finding.getType(), 
                                finding.getFinding(), 
                                finding.getRuleName(),
                                entropyLevel,
                                String.valueOf(reuseCount),
                                finding.getUrl()
                            });
                        }
                    }
                    
                    // Update reuse counts for all findings after loading
                    SwingUtilities.invokeLater(this::refreshReuseCounts);
                }
            }
        } catch (Exception e) {
            // Handle corrupt persistence data gracefully
            extension.log(JsMinerExtension.LogLevel.WARN, "Failed to load findings (data may be corrupt): " + e.getMessage());
            api.persistence().extensionData().deleteString(FINDINGS_KEY);
        }
    }
    
    private void refreshReuseCounts() {
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String finding = (String) tableModel.getValueAt(i, 2);
            java.util.Set<String> urls = secretToUrls.get(finding);
            if (urls != null) {
                tableModel.setValueAt(String.valueOf(urls.size()), i, 5);
            }
        }
    }
}