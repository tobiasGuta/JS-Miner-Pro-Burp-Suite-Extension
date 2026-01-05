package com.burp.custom.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;
import com.burp.custom.model.RegexRule;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

public class ConfigTab extends JPanel {

    private final MontoyaApi api;
    private final DefaultTableModel tableModel;
    private final Gson gson;
    private List<RegexRule> rules;
    private JCheckBox inScopeOnlyCheckbox;
    private JTextArea mimeTypesTextArea;
    private JTextArea noisePatternsTextArea;

    public ConfigTab(MontoyaApi api) {
        this.api = api;
        this.gson = new Gson();
        this.setLayout(new BorderLayout(0, 5)); // Add vertical gap

        // --- Top Panel for Scope, MIME types, and Noise Filters ---
        JPanel topContainerPanel = new JPanel(new BorderLayout(0, 5));
        topContainerPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Scope checkbox at the top
        inScopeOnlyCheckbox = new JCheckBox("Only analyze in-scope traffic", true);
        topContainerPanel.add(inScopeOnlyCheckbox, BorderLayout.NORTH);

        // Panel for the two text areas
        JPanel textAreasPanel = new JPanel(new GridLayout(1, 2, 5, 0)); // Horizontal gap

        // MIME Panel
        JPanel mimePanel = new JPanel(new BorderLayout());
        mimePanel.setBorder(BorderFactory.createTitledBorder("MIME Types to Scan"));
        mimeTypesTextArea = new JTextArea();
        mimeTypesTextArea.setRows(5); // Set preferred row count
        mimePanel.add(new JScrollPane(mimeTypesTextArea), BorderLayout.CENTER);
        textAreasPanel.add(mimePanel);

        // Noise Panel
        JPanel noisePanel = new JPanel(new BorderLayout());
        noisePanel.setBorder(BorderFactory.createTitledBorder("Noise Patterns to Exclude (Regex)"));
        noisePatternsTextArea = new JTextArea();
        noisePatternsTextArea.setRows(5); // Set consistent row count
        noisePanel.add(new JScrollPane(noisePatternsTextArea), BorderLayout.CENTER);
        textAreasPanel.add(noisePanel);

        topContainerPanel.add(textAreasPanel, BorderLayout.CENTER);
        this.add(topContainerPanel, BorderLayout.NORTH);

        // --- Rule Configuration Table ---
        Object[] columnNames = {"Active", "Name", "Regex", "Type"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Boolean.class : String.class;
            }
        };

        JTable table = new JTable(tableModel);
        JScrollPane scrollPane = new JScrollPane(table);
        this.add(scrollPane, BorderLayout.CENTER);

        // --- Control Buttons ---
        JPanel controlPanel = new JPanel();
        JButton addButton = new JButton("Add Rule");
        JButton deleteButton = new JButton("Delete Selected");
        JButton resetButton = new JButton("Reset to Defaults");
        JButton saveButton = new JButton("Save & Apply");

        controlPanel.add(addButton);
        controlPanel.add(deleteButton);
        controlPanel.add(resetButton);
        controlPanel.add(saveButton);
        this.add(controlPanel, BorderLayout.SOUTH);

        loadConfig();

        // Button Actions
        addButton.addActionListener(e -> tableModel.addRow(new Object[]{true, "New Rule", "", "GENERIC"}));
        deleteButton.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            if (selectedRow != -1) tableModel.removeRow(selectedRow);
        });
        resetButton.addActionListener(e -> {
            if (JOptionPane.showConfirmDialog(this, "This will reset rules and filters to their defaults. Continue?", "Confirm Reset", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                createDefaultRules();
                refreshTable();
                saveConfig();
            }
        });
        saveButton.addActionListener(e -> saveConfig());
    }

    private void loadConfig() {
        Preferences prefs = api.persistence().preferences();
        String json = prefs.getString("jsminer_rules");
        if (json == null || json.isEmpty()) {
            createDefaultRules();
        } else {
            Type listType = new TypeToken<ArrayList<RegexRule>>(){}.getType();
            rules = gson.fromJson(json, listType);
        }

        Boolean scopeOnly = prefs.getBoolean("jsminer_scope");
        inScopeOnlyCheckbox.setSelected(scopeOnly != null ? scopeOnly : true);

        String mimeTypes = prefs.getString("jsminer_mimetypes");
        mimeTypesTextArea.setText(mimeTypes != null ? mimeTypes : "text/html\napplication/javascript\napplication/json\napplication/xml\ntext/plain");

        String noisePatterns = prefs.getString("jsminer_noise");
        noisePatternsTextArea.setText(noisePatterns != null ? noisePatterns : "^\\.?\\.?/\n^[a-z]{2}(-[a-z]{2})?\\.js$\n\\.xml$\n^webpack\n^_ngcontent");

        refreshTable();
    }

    private void createDefaultRules() {
        rules = new ArrayList<>();
        // SECRETS
        rules.add(new RegexRule(true, "AWS Key ID", "(AKIA[0-9A-Z]{16})", "SECRET"));
        rules.add(new RegexRule(true, "Google API Key", "(AIza[0-9A-Za-z\\-_]{35})", "SECRET"));
        rules.add(new RegexRule(true, "Stripe Live Key", "(sk_live_[0-9a-zA-Z]{24,})", "SECRET"));
        rules.add(new RegexRule(true, "GitHub PAT", "(ghp_[0-9a-zA-Z]{36})", "SECRET"));
        rules.add(new RegexRule(true, "Slack Token", "(xox[baprs]-[0-9a-zA-Z\\-]{10,48})", "SECRET"));
        rules.add(new RegexRule(true, "JWT Token", "(eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]+)", "SECRET"));
        rules.add(new RegexRule(true, "Private Key", "(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)", "SECRET"));
        rules.add(new RegexRule(true, "MongoDB URL", "(mongodb(?:\\+srv)?://[^\\s\"'<>]+)", "SECRET"));
        rules.add(new RegexRule(true, "PostgreSQL URL", "(postgres(?:ql)?://[^\\s\"'<>]+)", "SECRET"));

        // ENDPOINTS
        rules.add(new RegexRule(true, "API Endpoint", "(?i)[\"']((?:https?:)?//[^\"']+/api/[a-zA-Z0-9/_-]+)[\"']", "ENDPOINT"));
        rules.add(new RegexRule(true, "API Path v1", "(?i)[\"'](/api/v?\\d*/[a-zA-Z0-9/_-]{2,})[\"']", "ENDPOINT"));
        rules.add(new RegexRule(true, "API Path v2", "(?i)[\"'](/v\\d+/[a-zA-Z0-9/_-]{2,})[\"']", "ENDPOINT"));
        rules.add(new RegexRule(true, "REST Path", "(?i)[\"'](/rest/[a-zA-Z0-9/_-]{2,})[\"']", "ENDPOINT"));
        rules.add(new RegexRule(true, "GraphQL Path", "(?i)[\"'](/graphql[a-zA-Z0-9/_-]*)[\"']", "ENDPOINT"));
        rules.add(new RegexRule(true, "Auth Path", "(?i)[\"'](/auth[a-zA-Z0-9/_-]*)[\"']", "ENDPOINT"));
        rules.add(new RegexRule(true, "Login Path", "(?i)[\"'](/login[a-zA-Z0-9/_-]*)[\"']", "ENDPOINT"));
        rules.add(new RegexRule(true, "Admin Path", "(?i)[\"'](/admin[a-zA-Z0-9/_-]*)[\"']", "ENDPOINT"));
        rules.add(new RegexRule(true, "Internal Path", "(?i)[\"'](/internal[a-zA-Z0-9/_-]*)[\"']", "ENDPOINT"));
        rules.add(new RegexRule(true, "Private Path", "(?i)[\"'](/private[a-zA-Z0-9/_-]*)[\"']", "ENDPOINT"));

        // URLs
        rules.add(new RegexRule(true, "Full URL", "[\"'](https?://[^\\s\"'<>]{10,})[\"']", "URL"));
        rules.add(new RegexRule(true, "WebSocket URL", "[\"'](wss?://[^\\s\"'<>]{10,})[\"']", "URL"));
        rules.add(new RegexRule(true, "S3 Bucket", "(https?://[a-zA-Z0-9.-]+\\.s3[a-zA-Z0-9.-]*\\.amazonaws\\.com[^\\s\"'<>']*)", "URL"));
        rules.add(new RegexRule(true, "Azure Blob URL", "(https?://[a-zA-Z0-9.-]+\\.blob\\.core\\.windows\\.net[^\\s\"'<>']*)", "URL"));
        rules.add(new RegexRule(true, "GCP Storage URL", "(https?://storage\\.googleapis\\.com/[^\\s\"'<>']*)", "URL"));

        // OTHER
        rules.add(new RegexRule(true, "Email Address", "([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6})", "INFO"));
        rules.add(new RegexRule(true, "Sensitive File", "(?i)[\"']([a-zA-Z0-9_/.-]+\\.(?:sql|csv|xlsx|xls|json|xml|yaml|yml|log|conf|ini|env|bak|key|pem|crt|p12|pfx|zip|tar|gz))[\"']", "FILE"));
    }

    private void refreshTable() {
        tableModel.setRowCount(0);
        for (RegexRule rule : rules) {
            tableModel.addRow(new Object[]{rule.isActive(), rule.getName(), rule.getRegex(), rule.getType()});
        }
    }

    public void saveConfig() {
        // Save rules from table
        List<RegexRule> newRules = new ArrayList<>();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            boolean active = (boolean) tableModel.getValueAt(i, 0);
            String name = (String) tableModel.getValueAt(i, 1);
            String regex = (String) tableModel.getValueAt(i, 2);
            String type = (String) tableModel.getValueAt(i, 3);
            newRules.add(new RegexRule(active, name, regex, type));
        }
        this.rules = newRules;

        // Persist all settings
        Preferences prefs = api.persistence().preferences();
        prefs.setString("jsminer_rules", gson.toJson(newRules));
        prefs.setBoolean("jsminer_scope", inScopeOnlyCheckbox.isSelected());
        prefs.setString("jsminer_mimetypes", mimeTypesTextArea.getText());
        prefs.setString("jsminer_noise", noisePatternsTextArea.getText());
    }

    public List<RegexRule> getRules() { return rules; }
    public boolean isScopeOnly() { return inScopeOnlyCheckbox.isSelected(); }
    public String[] getMimeTypes() { return mimeTypesTextArea.getText().split("\n"); }
    public String[] getNoisePatterns() { return noisePatternsTextArea.getText().split("\n"); }
}