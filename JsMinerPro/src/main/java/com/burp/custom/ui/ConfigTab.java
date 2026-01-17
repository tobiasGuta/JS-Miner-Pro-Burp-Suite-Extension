package com.burp.custom.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import com.burp.custom.JsMinerExtension;
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
    private JTextField maxFileSizeField; // New field for file size limit
    private JsMinerExtension extension;

    // Define defaults as constants
    private static final String DEFAULT_MIME_TYPES = "script\ntext/html\napplication/javascript\napplication/json\napplication/xml\ntext/plain";
    private static final String DEFAULT_NOISE_PATTERNS = "^\\.?\\.?/\n^[a-z]{2}(-[a-z]{2})?\\.js$\n\\.xml$\n^webpack\n^_ngcontent";
    private static final double DEFAULT_MAX_FILE_SIZE_MB = 1.0;


    public ConfigTab(MontoyaApi api, JsMinerExtension extension) {
        this.api = api;
        this.extension = extension;
        this.gson = new Gson();
        this.setLayout(new BorderLayout(0, 5)); // Add vertical gap

        // --- Top Panel for Scope, MIME types, and Noise Filters ---
        JPanel topContainerPanel = new JPanel(new BorderLayout(0, 5));
        topContainerPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Scope and Performance Panel
        JPanel settingsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        inScopeOnlyCheckbox = new JCheckBox("Only analyze in-scope traffic", true);
        
        JLabel maxFileSizeLabel = new JLabel("Max File Size (MB):");
        maxFileSizeField = new JTextField(String.valueOf(DEFAULT_MAX_FILE_SIZE_MB), 5);
        maxFileSizeField.setToolTipText("Files larger than this will be skipped to prevent freezing.");
        
        settingsPanel.add(inScopeOnlyCheckbox);
        settingsPanel.add(Box.createHorizontalStrut(20)); // Spacer
        settingsPanel.add(maxFileSizeLabel);
        settingsPanel.add(maxFileSizeField);
        
        topContainerPanel.add(settingsPanel, BorderLayout.NORTH);

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
                mimeTypesTextArea.setText(DEFAULT_MIME_TYPES); 
                noisePatternsTextArea.setText(DEFAULT_NOISE_PATTERNS); 
                inScopeOnlyCheckbox.setSelected(true); 
                maxFileSizeField.setText(String.valueOf(DEFAULT_MAX_FILE_SIZE_MB)); // Reset file size
                refreshTable();
                saveConfig();
            }
        });
        saveButton.addActionListener(e -> {
            saveConfig();
            JOptionPane.showMessageDialog(this, "Configuration saved successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
        });
    }

    private void loadConfig() {
        PersistedObject prefs = api.persistence().extensionData();
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
        mimeTypesTextArea.setText(mimeTypes != null ? mimeTypes : DEFAULT_MIME_TYPES);

        String noisePatterns = prefs.getString("jsminer_noise");
        noisePatternsTextArea.setText(noisePatterns != null ? noisePatterns : DEFAULT_NOISE_PATTERNS);
        
        // Load Max File Size (Stored as String because PersistedObject doesn't support Double)
        String maxFileSizeStr = prefs.getString("jsminer_max_file_size");
        if (maxFileSizeStr == null) {
            maxFileSizeField.setText(String.valueOf(DEFAULT_MAX_FILE_SIZE_MB));
        } else {
            maxFileSizeField.setText(maxFileSizeStr);
        }

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

        // ENDPOINTS & PATHS
        rules.add(new RegexRule(true, "Generic Path", "['\"](/[a-zA-Z0-9/._-]{10,})['\"]", "ENDPOINT"));
        rules.add(new RegexRule(true, "API Endpoint", "(?i)[\"']((?:https?:)?//[^\"']+/api/[a-zA-Z0-9/_-]+)[\"']", "ENDPOINT"));
        rules.add(new RegexRule(true, "GraphQL Path", "(?i)[\"'](/graphql[a-zA-Z0-9/_-]*)[\"']", "ENDPOINT"));

        // URLs
        rules.add(new RegexRule(true, "Full URL", "[\"'](https?://[^\\s\"'<>]{10,})[\"']", "URL"));
        rules.add(new RegexRule(true, "WebSocket URL", "[\"'](wss?://[^\\s\"'<>]{10,})[\"']", "URL"));
        rules.add(new RegexRule(true, "S3 Bucket", "(https?://[a-zA-Z0-9.-]+\\.s3[a-zA-Z0-9.-]*\\.amazonaws\\.com[^\\s\"'<>']*)", "URL"));
        rules.add(new RegexRule(true, "Azure Blob URL", "(https?://[a-zA-Z0-9.-]+\\.blob\\.core\\.windows\\.net[^\\s\"'<>']*)", "URL"));
        rules.add(new RegexRule(true, "GCP Storage URL", "(https?://storage\\.googleapis\\.com/[^\\s\"'<>']*)", "URL"));

        // OTHER
        rules.add(new RegexRule(true, "Email Address", "([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6})", "INFO"));
        rules.add(new RegexRule(true, "Sensitive File", "(?i)[\"']([a-zA-Z0-9_/.-]+\\.(?:sql|csv|json|xml|yml|log|conf|ini|env|bak|key|pem|crt|pfx))[\"']", "FILE"));
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
        PersistedObject prefs = api.persistence().extensionData();
        prefs.setString("jsminer_rules", gson.toJson(newRules));
        prefs.setBoolean("jsminer_scope", inScopeOnlyCheckbox.isSelected());
        prefs.setString("jsminer_mimetypes", mimeTypesTextArea.getText());
        prefs.setString("jsminer_noise", noisePatternsTextArea.getText());
        
        // Save Max File Size (as String)
        try {
            // Validate it's a number
            Double.parseDouble(maxFileSizeField.getText());
            prefs.setString("jsminer_max_file_size", maxFileSizeField.getText());
        } catch (NumberFormatException e) {
            // Fallback to default if invalid input
            prefs.setString("jsminer_max_file_size", String.valueOf(DEFAULT_MAX_FILE_SIZE_MB));
        }
        
        // Notify the main extension to update its live patterns
        if (extension != null) {
            extension.updateNoisePatterns();
        }
    }

    public List<RegexRule> getRules() { return rules; }
    public boolean isScopeOnly() { return inScopeOnlyCheckbox.isSelected(); }
    public String[] getMimeTypes() { return mimeTypesTextArea.getText().split("\n"); }
    public String[] getNoisePatterns() { return noisePatternsTextArea.getText().split("\n"); }
    
    public double getMaxFileSizeMb() {
        try {
            return Double.parseDouble(maxFileSizeField.getText());
        } catch (NumberFormatException e) {
            return DEFAULT_MAX_FILE_SIZE_MB;
        }
    }
}