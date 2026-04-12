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

public class ResultsTab extends JPanel {

    private final MontoyaApi api;
    private final JsMinerExtension extension;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final Gson gson;

    private final List<Finding> findingsList = new ArrayList<>();
    // URL-scoped dedup — same secret on same URL is one finding
    private final Set<String> uniqueUrlScopedKeys = new HashSet<>();
    // Global secret dedup — tracks every URL a given secret was found on
    private final Map<String, Set<String>> secretToUrls = new LinkedHashMap<>();
    // Map from finding value to table row indices for O(1) reuse-count updates
    private final Map<String, List<Integer>> findingToRows = new HashMap<>();

    private static final String FINDINGS_KEY = "jsminer_findings_v2";

    private JComboBox<String> severityFilter;
    private JComboBox<String> typeFilter;
    private JComboBox<String> entropyFilter;
    private JTextField searchField;
    private JLabel statsLabel;

    // Column indices — kept as constants so a column reorder only needs one change here
    private static final int COL_SEVERITY = 0;
    private static final int COL_TYPE     = 1;
    private static final int COL_FINDING  = 2;
    private static final int COL_RULE     = 3;
    private static final int COL_ENTROPY  = 4;
    private static final int COL_REUSE    = 5;
    private static final int COL_CONTEXT  = 6;
    private static final int COL_URL      = 7;

    public ResultsTab(MontoyaApi api, JsMinerExtension extension) {
        this.api       = api;
        this.extension = extension;
        this.gson      = new GsonBuilder().setPrettyPrinting().create();
        setLayout(new BorderLayout());

        // ---- Table ----
        String[] columns = {"Severity", "Type", "Finding", "Rule", "Entropy", "Reuse", "Context", "Source URL"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);

        table.getColumnModel().getColumn(COL_SEVERITY).setPreferredWidth(60);
        table.getColumnModel().getColumn(COL_TYPE).setPreferredWidth(65);
        table.getColumnModel().getColumn(COL_FINDING).setPreferredWidth(260);
        table.getColumnModel().getColumn(COL_RULE).setPreferredWidth(120);
        table.getColumnModel().getColumn(COL_ENTROPY).setPreferredWidth(70);
        table.getColumnModel().getColumn(COL_REUSE).setPreferredWidth(45);
        table.getColumnModel().getColumn(COL_CONTEXT).setPreferredWidth(300);
        table.getColumnModel().getColumn(COL_URL).setPreferredWidth(230);

        // Entropy colour renderer
        table.getColumnModel().getColumn(COL_ENTROPY).setCellRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean foc, int r, int c) {
                Component comp = super.getTableCellRendererComponent(t, v, sel, foc, r, c);
                if (!sel) {
                    String val = String.valueOf(v);
                    if ("VERY HIGH".equals(val)) { comp.setBackground(new Color(255, 80, 80));  comp.setForeground(Color.WHITE); }
                    else if ("HIGH".equals(val)) { comp.setBackground(new Color(255, 170, 80)); comp.setForeground(Color.BLACK); }
                    else if ("MEDIUM".equals(val)) { comp.setBackground(new Color(255, 255, 130)); comp.setForeground(Color.BLACK); }
                    else { comp.setBackground(Color.WHITE); comp.setForeground(Color.BLACK); }
                }
                return comp;
            }
        });

        // Reuse colour renderer
        table.getColumnModel().getColumn(COL_REUSE).setCellRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean foc, int r, int c) {
                Component comp = super.getTableCellRendererComponent(t, v, sel, foc, r, c);
                if (!sel) {
                    int reuse = 1;
                    try { reuse = Integer.parseInt(String.valueOf(v)); } catch (Exception ignored) {}
                    if (reuse > 5)       { comp.setBackground(new Color(255, 50, 50));   comp.setForeground(Color.WHITE); }
                    else if (reuse > 2)  { comp.setBackground(new Color(255, 150, 50));  comp.setForeground(Color.BLACK); }
                    else if (reuse > 1)  { comp.setBackground(new Color(255, 220, 100)); comp.setForeground(Color.BLACK); }
                    else                 { comp.setBackground(Color.WHITE);               comp.setForeground(Color.BLACK); }
                }
                setHorizontalAlignment(SwingConstants.CENTER);
                return comp;
            }
        });

        // Severity colour renderer
        table.getColumnModel().getColumn(COL_SEVERITY).setCellRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean foc, int r, int c) {
                Component comp = super.getTableCellRendererComponent(t, v, sel, foc, r, c);
                if (!sel) {
                    String val = String.valueOf(v);
                    switch (val) {
                        case "HIGH":   comp.setBackground(new Color(255, 80, 80));   comp.setForeground(Color.WHITE); break;
                        case "MEDIUM": comp.setBackground(new Color(255, 170, 80));  comp.setForeground(Color.BLACK); break;
                        case "LOW":    comp.setBackground(new Color(255, 255, 130)); comp.setForeground(Color.BLACK); break;
                        default:       comp.setBackground(Color.WHITE);               comp.setForeground(Color.BLACK);
                    }
                }
                setHorizontalAlignment(SwingConstants.CENTER);
                return comp;
            }
        });

        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
        sorter.setComparator(COL_SEVERITY, (s1, s2) -> Integer.compare(getSeverityOrder((String)s2), getSeverityOrder((String)s1)));
        sorter.setComparator(COL_ENTROPY,  (s1, s2) -> Integer.compare(getEntropyOrder((String)s2),  getEntropyOrder((String)s1)));
        sorter.setComparator(COL_REUSE, (s1, s2) -> {
            int v1 = 1, v2 = 1;
            try { v1 = Integer.parseInt((String)s1); } catch (Exception ignored) {}
            try { v2 = Integer.parseInt((String)s2); } catch (Exception ignored) {}
            return Integer.compare(v2, v1);
        });
        table.setRowSorter(sorter);

        JScrollPane tableScroll = new JScrollPane(table);

        // ---- Editors ----
        requestEditor  = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        JSplitPane editorSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
            requestEditor.uiComponent(), responseEditor.uiComponent());
        editorSplit.setResizeWeight(0.5);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, editorSplit);
        mainSplit.setResizeWeight(0.6);

        // ---- Control panel ----
        JPanel controlPanel = new JPanel(new BorderLayout());

        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        filterPanel.add(new JLabel("Severity:"));
        severityFilter = new JComboBox<>(new String[]{"All", "HIGH", "MEDIUM", "LOW", "INFO"});
        severityFilter.addActionListener(e -> applyFilters());
        filterPanel.add(severityFilter);

        filterPanel.add(Box.createHorizontalStrut(8));
        filterPanel.add(new JLabel("Type:"));
        typeFilter = new JComboBox<>(new String[]{"All", "SECRET", "URL", "ENDPOINT", "FILE", "INFO"});
        typeFilter.addActionListener(e -> applyFilters());
        filterPanel.add(typeFilter);

        filterPanel.add(Box.createHorizontalStrut(8));
        filterPanel.add(new JLabel("Entropy:"));
        entropyFilter = new JComboBox<>(new String[]{"All", "VERY HIGH", "HIGH", "MEDIUM", "LOW"});
        entropyFilter.addActionListener(e -> applyFilters());
        filterPanel.add(entropyFilter);

        filterPanel.add(Box.createHorizontalStrut(8));
        filterPanel.add(new JLabel("Search:"));
        searchField = new JTextField(18);
        searchField.addActionListener(e -> applyFilters());
        filterPanel.add(searchField);
        JButton filterBtn = new JButton("Filter");
        filterBtn.addActionListener(e -> applyFilters());
        filterPanel.add(filterBtn);

        controlPanel.add(filterPanel, BorderLayout.NORTH);

        statsLabel = new JLabel("0 findings");
        statsLabel.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 0));
        controlPanel.add(statsLabel, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton scanBtn = new JButton("Scan Proxy History");
        scanBtn.setBackground(new Color(60, 120, 180));
        scanBtn.setForeground(Color.WHITE);
        scanBtn.setToolTipText("Scan all Proxy history for secrets and endpoints");
        scanBtn.addActionListener(e -> {
            scanBtn.setEnabled(false);
            scanBtn.setText("Scanning...");
            extension.scanProxyHistory();
            new javax.swing.Timer(2000, evt -> {
                scanBtn.setEnabled(true);
                scanBtn.setText("Scan Proxy History");
                ((javax.swing.Timer) evt.getSource()).stop();
            }).start();
        });

        JButton clearBtn      = new JButton("Clear Results");
        JButton saveBtn       = new JButton("Save Results");
        JButton exportJsonBtn = new JButton("Export JSON");
        JButton exportCsvBtn  = new JButton("Export CSV");

        clearBtn.addActionListener(e -> clearResults());
        saveBtn.addActionListener(e -> {
            saveFindings();
            JOptionPane.showMessageDialog(this, "Results saved.", "Saved", JOptionPane.INFORMATION_MESSAGE);
        });
        exportJsonBtn.addActionListener(e -> exportFindings("json"));
        exportCsvBtn.addActionListener(e -> exportFindings("csv"));

        buttonPanel.add(scanBtn);
        buttonPanel.add(Box.createHorizontalStrut(12));
        buttonPanel.add(clearBtn);
        buttonPanel.add(saveBtn);
        buttonPanel.add(exportJsonBtn);
        buttonPanel.add(exportCsvBtn);
        controlPanel.add(buttonPanel, BorderLayout.SOUTH);

        add(controlPanel, BorderLayout.NORTH);
        add(mainSplit,    BorderLayout.CENTER);

        // Selection listener
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = table.getSelectedRow();
                if (viewRow >= 0) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    if (modelRow >= 0 && modelRow < findingsList.size()) {
                        displayFinding(findingsList.get(modelRow));
                    }
                }
            }
        });

        setupContextMenu();
        loadFindings();
    }

    // -------------------------------------------------------------------------
    // Adding findings
    // -------------------------------------------------------------------------

    public void addFinding(String type, String finding, String ruleName, String url,
                           HttpRequestResponse reqResp, int start, int end,
                           String severity, String context) {

        Finding newFinding = new Finding(type, finding, ruleName, url, reqResp, start, end, severity, context);
        String urlKey = newFinding.getUrlScopedKey();

        // Only add if this exact (finding, type, url) combo hasn't been seen
        if (!uniqueUrlScopedKeys.add(urlKey)) return;

        EntropyAnalyzer.EntropyResult entropyResult = EntropyAnalyzer.analyze(finding);
        String entropyLevel = entropyResult.level;

        // Track reuse across URLs — the secretToUrls map keys on finding VALUE only
        secretToUrls.computeIfAbsent(finding, k -> new LinkedHashSet<>()).add(url);
        int reuseCount = secretToUrls.get(finding).size();

        SwingUtilities.invokeLater(() -> {
            int newRow = findingsList.size();
            findingsList.add(newFinding);

            tableModel.addRow(new Object[]{
                severity, type, finding, ruleName,
                entropyLevel, String.valueOf(reuseCount), context, url
            });

            // Track which rows contain this finding value for O(1) reuse updates
            findingToRows.computeIfAbsent(finding, k -> new ArrayList<>()).add(newRow);

            // If this finding already appeared on other URLs, update all prior rows
            if (reuseCount > 1) {
                List<Integer> rows = findingToRows.get(finding);
                for (int rowIdx : rows) {
                    tableModel.setValueAt(String.valueOf(reuseCount), rowIdx, COL_REUSE);
                }
            }

            statsLabel.setText(findingsList.size() + " finding" + (findingsList.size() == 1 ? "" : "s"));
        });
    }

    // -------------------------------------------------------------------------
    // Display / context menu
    // -------------------------------------------------------------------------

    private void displayFinding(Finding finding) {
        if (finding.getRequestResponse() != null) {
            requestEditor.setRequest(finding.getRequestResponse().request());
            responseEditor.setResponse(finding.getRequestResponse().response());
        } else if (finding.getRequestString() != null && finding.getResponseString() != null) {
            requestEditor.setRequest(HttpRequest.httpRequest(finding.getRequestString()));
            responseEditor.setResponse(HttpResponse.httpResponse(finding.getResponseString()));
        } else {
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
        }
        if (responseEditor.getResponse() != null) {
            responseEditor.setSearchExpression(finding.getFinding());
        }
    }

    private void setupContextMenu() {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem copyFinding = new JMenuItem("Copy Finding");
        copyFinding.addActionListener(e -> copyToClipboard(getSelectedFinding() != null ? getSelectedFinding().getFinding() : ""));
        menu.add(copyFinding);

        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> copyToClipboard(getSelectedFinding() != null ? getSelectedFinding().getUrl() : ""));
        menu.add(copyUrl);

        JMenuItem copyContext = new JMenuItem("Copy Context");
        copyContext.addActionListener(e -> copyToClipboard(getSelectedFinding() != null ? getSelectedFinding().getContext() : ""));
        menu.add(copyContext);

        menu.addSeparator();

        JMenuItem sendRepeater = new JMenuItem("Send to Repeater");
        sendRepeater.addActionListener(e -> sendToTool("repeater"));
        menu.add(sendRepeater);

        JMenuItem sendIntruder = new JMenuItem("Send to Intruder");
        sendIntruder.addActionListener(e -> sendToTool("intruder"));
        menu.add(sendIntruder);

        JMenuItem sendOrganizer = new JMenuItem("Send to Organizer");
        sendOrganizer.addActionListener(e -> sendToTool("organizer"));
        menu.add(sendOrganizer);

        menu.addSeparator();

        JMenuItem delete = new JMenuItem("Delete Finding");
        delete.addActionListener(e -> deleteSelectedFinding());
        menu.add(delete);

        table.setComponentPopupMenu(menu);
    }

    private Finding getSelectedFinding() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return null;
        int modelRow = table.convertRowIndexToModel(viewRow);
        return (modelRow >= 0 && modelRow < findingsList.size()) ? findingsList.get(modelRow) : null;
    }

    private void copyToClipboard(String text) {
        StringSelection sel = new StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, sel);
    }

    private void sendToTool(String tool) {
        Finding f = getSelectedFinding();
        if (f == null) return;
        HttpRequest req = null;
        if (f.getRequestResponse() != null) req = f.getRequestResponse().request();
        else if (f.getRequestString() != null) req = HttpRequest.httpRequest(f.getRequestString());
        if (req == null) return;

        switch (tool) {
            case "repeater":  api.repeater().sendToRepeater(req, "JS Miner: " + f.getRuleName()); break;
            case "intruder":  api.intruder().sendToIntruder(req); break;
            case "organizer":
                if (f.getRequestResponse() != null) {
                    api.organizer().sendToOrganizer(f.getRequestResponse());
                } else if (f.getRequestString() != null && f.getResponseString() != null) {
                    api.organizer().sendToOrganizer(HttpRequestResponse.httpRequestResponse(
                        HttpRequest.httpRequest(f.getRequestString()),
                        HttpResponse.httpResponse(f.getResponseString())));
                }
                break;
        }
    }

    private void deleteSelectedFinding() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow >= 0 && modelRow < findingsList.size()) {
            Finding f = findingsList.get(modelRow);
            uniqueUrlScopedKeys.remove(f.getUrlScopedKey());
            findingsList.remove(modelRow);
            tableModel.removeRow(modelRow);
            statsLabel.setText(findingsList.size() + " finding" + (findingsList.size() == 1 ? "" : "s"));
        }
    }

    // -------------------------------------------------------------------------
    // Filters
    // -------------------------------------------------------------------------

    private void applyFilters() {
        String sev     = (String) severityFilter.getSelectedItem();
        String type    = (String) typeFilter.getSelectedItem();
        String entropy = (String) entropyFilter.getSelectedItem();
        String search  = searchField.getText().toLowerCase();

        TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) table.getRowSorter();
        sorter.setRowFilter(new javax.swing.RowFilter<DefaultTableModel, Integer>() {
            @Override public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
                String rowSev    = (String) entry.getValue(COL_SEVERITY);
                String rowType   = (String) entry.getValue(COL_TYPE);
                String rowFind   = ((String) entry.getValue(COL_FINDING)).toLowerCase();
                String rowEnt    = (String) entry.getValue(COL_ENTROPY);
                String rowUrl    = ((String) entry.getValue(COL_URL)).toLowerCase();
                String rowCtx    = ((String) entry.getValue(COL_CONTEXT)).toLowerCase();
                boolean sevMatch = "All".equals(sev)     || sev.equals(rowSev);
                boolean typMatch = "All".equals(type)    || type.equals(rowType);
                boolean entMatch = "All".equals(entropy) || entropy.equals(rowEnt);
                boolean srcMatch = search.isEmpty() || rowFind.contains(search) || rowUrl.contains(search) || rowCtx.contains(search);
                return sevMatch && typMatch && entMatch && srcMatch;
            }
        });
    }

    // -------------------------------------------------------------------------
    // Export — with sensitive data warning
    // -------------------------------------------------------------------------

    private void exportFindings(String format) {
        // Warn before exporting plaintext secrets
        int confirm = JOptionPane.showConfirmDialog(this,
            "The export file will contain plaintext secrets and sensitive findings.\n" +
            "Ensure the file is stored securely and not committed to version control.\n\nProceed?",
            "Security Warning", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Findings");
        String ext = format.equals("json") ? "json" : "csv";
        chooser.setFileFilter(new FileNameExtensionFilter(ext.toUpperCase() + " files", ext));
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        chooser.setSelectedFile(new File("jsminer_findings_" + timestamp + "." + ext));

        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            if (!file.getName().endsWith("." + ext)) file = new File(file.getAbsolutePath() + "." + ext);
            try (FileWriter writer = new FileWriter(file)) {
                if ("json".equals(format)) exportToJson(writer);
                else exportToCsv(writer);
                JOptionPane.showMessageDialog(this, "Exported " + findingsList.size() + " findings to: " + file.getName(),
                    "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportToJson(FileWriter writer) throws IOException {
        List<Map<String, Object>> data = new ArrayList<>();
        for (Finding f : findingsList) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("severity",  f.getSeverity());
            item.put("type",      f.getType());
            item.put("finding",   f.getFinding());
            item.put("ruleName",  f.getRuleName());
            item.put("url",       f.getUrl());
            item.put("context",   f.getContext());
            item.put("timestamp", f.getTimestamp());
            item.put("reuseCount", secretToUrls.getOrDefault(f.getFinding(), Collections.emptySet()).size());
            data.add(item);
        }
        writer.write(gson.toJson(data));
    }

    private void exportToCsv(FileWriter writer) throws IOException {
        // All fields quoted — fixes the original bug where Rule Name was unquoted
        writer.write("\"Severity\",\"Type\",\"Finding\",\"Rule Name\",\"Entropy\",\"Reuse\",\"Context\",\"URL\"\n");
        for (Finding f : findingsList) {
            EntropyAnalyzer.EntropyResult er = EntropyAnalyzer.analyze(f.getFinding());
            int reuse = secretToUrls.getOrDefault(f.getFinding(), Collections.emptySet()).size();
            writer.write(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%d\",\"%s\",\"%s\"\n",
                csv(f.getSeverity()), csv(f.getType()), csv(f.getFinding()),
                csv(f.getRuleName()), csv(er.level), reuse,
                csv(f.getContext()), csv(f.getUrl())));
        }
    }

    private String csv(String v) {
        if (v == null) return "";
        return v.replace("\"", "\"\"").replace("\n", " ").replace("\r", "");
    }

    // -------------------------------------------------------------------------
    // Persistence
    // -------------------------------------------------------------------------

    public void saveAllFindings() { saveFindings(); }

    private void saveFindings() {
        try {
            api.persistence().extensionData().setString(FINDINGS_KEY, gson.toJson(findingsList));
        } catch (Exception e) {
            extension.log(JsMinerExtension.LogLevel.ERROR, "Failed to save findings: " + e.getMessage());
        }
    }

    private void loadFindings() {
        try {
            PersistedObject prefs = api.persistence().extensionData();
            String json = prefs.getString(FINDINGS_KEY);
            if (json == null || json.isEmpty()) return;

            Type listType = new TypeToken<ArrayList<Finding>>(){}.getType();
            List<Finding> loaded = gson.fromJson(json, listType);
            if (loaded == null) return;

            for (Finding f : loaded) {
                if (!uniqueUrlScopedKeys.add(f.getUrlScopedKey())) continue;
                findingsList.add(f);
                EntropyAnalyzer.EntropyResult er = EntropyAnalyzer.analyze(f.getFinding());
                secretToUrls.computeIfAbsent(f.getFinding(), k -> new LinkedHashSet<>()).add(f.getUrl());
                int reuse = secretToUrls.get(f.getFinding()).size();

                int rowIdx = findingsList.size() - 1;
                findingToRows.computeIfAbsent(f.getFinding(), k -> new ArrayList<>()).add(rowIdx);

                tableModel.addRow(new Object[]{
                    f.getSeverity(), f.getType(), f.getFinding(), f.getRuleName(),
                    er.level, String.valueOf(reuse), f.getContext(), f.getUrl()
                });
            }

            // Refresh reuse counts after all rows are loaded
            SwingUtilities.invokeLater(() -> {
                for (Map.Entry<String, List<Integer>> entry : findingToRows.entrySet()) {
                    int count = secretToUrls.getOrDefault(entry.getKey(), Collections.emptySet()).size();
                    for (int idx : entry.getValue()) {
                        tableModel.setValueAt(String.valueOf(count), idx, COL_REUSE);
                    }
                }
                statsLabel.setText(findingsList.size() + " finding" + (findingsList.size() == 1 ? "" : "s"));
            });

        } catch (Exception e) {
            extension.log(JsMinerExtension.LogLevel.WARN, "Failed to load findings: " + e.getMessage());
            api.persistence().extensionData().deleteString(FINDINGS_KEY);
        }
    }

    private void clearResults() {
        SwingUtilities.invokeLater(() -> {
            tableModel.setRowCount(0);
            findingsList.clear();
            uniqueUrlScopedKeys.clear();
            secretToUrls.clear();
            findingToRows.clear();
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
            api.persistence().extensionData().deleteString(FINDINGS_KEY);
            statsLabel.setText("0 findings");
        });
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private int getSeverityOrder(String s) {
        switch (s == null ? "" : s.toUpperCase()) {
            case "HIGH": return 4; case "MEDIUM": return 3; case "LOW": return 2; case "INFO": return 1; default: return 0;
        }
    }

    private int getEntropyOrder(String s) {
        switch (s == null ? "" : s.toUpperCase()) {
            case "VERY HIGH": return 4; case "HIGH": return 3; case "MEDIUM": return 2; case "LOW": return 1; default: return 0;
        }
    }
}
