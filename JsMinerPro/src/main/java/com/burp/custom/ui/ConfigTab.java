package com.burp.custom.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import com.burp.custom.JsMinerExtension;
import com.burp.custom.model.RegexRule;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.lang.reflect.Type;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

public class ConfigTab extends JPanel {

    private final MontoyaApi api;
    private DefaultTableModel tableModel;
    private JTable table;
    private final Gson gson;
    private List<RegexRule> rules;
    private JCheckBox inScopeOnlyCheckbox;
    private JTextArea mimeTypesTextArea;
    private JTextArea noisePatternsTextArea;
    private JTextArea noiseDomainsTextArea;
    private JTextArea modulePrefixesTextArea;
    private JTextField maxFileSizeField;
    private JComboBox<String> logLevelCombo;
    private JsMinerExtension extension;
    private JLabel regexValidationLabel;

    // Define defaults as constants
    private static final String DEFAULT_MIME_TYPES = "script\ntext/html\napplication/javascript\napplication/json\napplication/xml\ntext/plain";
    private static final String DEFAULT_NOISE_PATTERNS = "^\\.?\\.?/\n^[a-z]{2}(-[a-z]{2})?\\.js$\n\\.xml$\n^webpack\n^_ngcontent";
    private static final String DEFAULT_NOISE_DOMAINS = "www.w3.org\nschemas.openxmlformats.org\nschemas.microsoft.com\npurl.org\nopenoffice.org\ndocs.oasis-open.org\nexample.com\ntest.com\nlocalhost\n127.0.0.1\nnpmjs.org\ngithub.com";
    private static final String DEFAULT_MODULE_PREFIXES = "./\n../\n.../\n./lib\n../lib\n./utils\n../utils\n./node_modules\n./src\n./dist";
    private static final double DEFAULT_MAX_FILE_SIZE_MB = 1.0;


    public ConfigTab(MontoyaApi api, JsMinerExtension extension) {
        this.api = api;
        this.extension = extension;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        this.setLayout(new BorderLayout(0, 5));

        // Create main tabbed pane for config sections
        JTabbedPane configTabs = new JTabbedPane();
        
        // === General Settings Panel ===
        JPanel generalPanel = createGeneralSettingsPanel();
        configTabs.addTab("General", generalPanel);
        
        // === Noise Filtering Panel ===
        JPanel noisePanel = createNoiseFilteringPanel();
        configTabs.addTab("Noise Filtering", noisePanel);

        // === Rule Configuration Table ===
        JPanel rulesPanel = createRulesPanel();
        configTabs.addTab("Rules", rulesPanel);

        this.add(configTabs, BorderLayout.CENTER);

        // --- Control Buttons ---
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton saveButton = new JButton("Save & Apply");
        JButton resetButton = new JButton("Reset to Defaults");
        JButton importButton = new JButton("Import Rules");
        JButton exportButton = new JButton("Export Rules");

        saveButton.addActionListener(e -> {
            if (validateAllRules()) {
                saveConfig();
                JOptionPane.showMessageDialog(this, "Configuration saved successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        
        resetButton.addActionListener(e -> {
            if (JOptionPane.showConfirmDialog(this, "This will reset ALL settings to defaults. Continue?", 
                    "Confirm Reset", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                resetToDefaults();
            }
        });
        
        importButton.addActionListener(e -> importRules());
        exportButton.addActionListener(e -> exportRules());

        controlPanel.add(saveButton);
        controlPanel.add(resetButton);
        controlPanel.add(Box.createHorizontalStrut(20));
        controlPanel.add(importButton);
        controlPanel.add(exportButton);
        
        this.add(controlPanel, BorderLayout.SOUTH);

        loadConfig();
    }

    private JPanel createGeneralSettingsPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Settings grid
        JPanel settingsGrid = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Row 0: Scope checkbox
        gbc.gridx = 0; gbc.gridy = 0;
        inScopeOnlyCheckbox = new JCheckBox("Only analyze in-scope traffic", true);
        settingsGrid.add(inScopeOnlyCheckbox, gbc);

        // Row 1: Max file size
        gbc.gridx = 0; gbc.gridy = 1;
        settingsGrid.add(new JLabel("Max File Size (MB):"), gbc);
        gbc.gridx = 1;
        maxFileSizeField = new JTextField(String.valueOf(DEFAULT_MAX_FILE_SIZE_MB), 8);
        maxFileSizeField.setToolTipText("Files larger than this will be skipped to prevent freezing.");
        settingsGrid.add(maxFileSizeField, gbc);

        // Row 2: Log level
        gbc.gridx = 0; gbc.gridy = 2;
        settingsGrid.add(new JLabel("Log Level:"), gbc);
        gbc.gridx = 1;
        logLevelCombo = new JComboBox<>(new String[]{"DEBUG", "INFO", "WARN", "ERROR"});
        logLevelCombo.setSelectedItem("INFO");
        logLevelCombo.setToolTipText("Controls verbosity of logging output.");
        settingsGrid.add(logLevelCombo, gbc);

        panel.add(settingsGrid, BorderLayout.NORTH);

        // MIME types
        JPanel mimePanel = new JPanel(new BorderLayout());
        mimePanel.setBorder(BorderFactory.createTitledBorder("MIME Types to Scan (one per line)"));
        mimeTypesTextArea = new JTextArea();
        mimeTypesTextArea.setRows(8);
        mimePanel.add(new JScrollPane(mimeTypesTextArea), BorderLayout.CENTER);

        panel.add(mimePanel, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createNoiseFilteringPanel() {
        JPanel panel = new JPanel(new GridLayout(2, 2, 10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Noise patterns (regex)
        JPanel noisePatternsPanel = new JPanel(new BorderLayout());
        noisePatternsPanel.setBorder(BorderFactory.createTitledBorder("Noise Patterns (Regex, one per line)"));
        noisePatternsTextArea = new JTextArea();
        noisePatternsTextArea.setRows(6);
        noisePatternsPanel.add(new JScrollPane(noisePatternsTextArea), BorderLayout.CENTER);
        panel.add(noisePatternsPanel);

        // Noise domains
        JPanel noiseDomainsPanel = new JPanel(new BorderLayout());
        noiseDomainsPanel.setBorder(BorderFactory.createTitledBorder("Noise Domains (one per line)"));
        noiseDomainsTextArea = new JTextArea();
        noiseDomainsTextArea.setRows(6);
        noiseDomainsPanel.add(new JScrollPane(noiseDomainsTextArea), BorderLayout.CENTER);
        panel.add(noiseDomainsPanel);

        // Module prefixes
        JPanel modulePrefixesPanel = new JPanel(new BorderLayout());
        modulePrefixesPanel.setBorder(BorderFactory.createTitledBorder("Module Prefixes to Ignore (one per line)"));
        modulePrefixesTextArea = new JTextArea();
        modulePrefixesTextArea.setRows(6);
        modulePrefixesPanel.add(new JScrollPane(modulePrefixesTextArea), BorderLayout.CENTER);
        panel.add(modulePrefixesPanel);

        // Help panel
        JPanel helpPanel = new JPanel(new BorderLayout());
        helpPanel.setBorder(BorderFactory.createTitledBorder("Help"));
        JTextArea helpText = new JTextArea(
            "Noise Patterns: Regex patterns to exclude from findings.\n" +
            "Example: ^webpack will exclude webpack-related paths.\n\n" +
            "Noise Domains: Domains to ignore in URL/endpoint findings.\n" +
            "Example: example.com, localhost\n\n" +
            "Module Prefixes: Path prefixes to ignore (common JS imports).\n" +
            "Example: ./, ../, ./node_modules"
        );
        helpText.setEditable(false);
        helpText.setBackground(panel.getBackground());
        helpText.setFont(helpText.getFont().deriveFont(Font.PLAIN, 11f));
        helpPanel.add(helpText, BorderLayout.CENTER);
        panel.add(helpPanel);

        return panel;
    }

    private JPanel createRulesPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Table with severity column
        String[] columnNames = {"Active", "Name", "Regex", "Type", "Severity"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Boolean.class : String.class;
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return true;
            }
        };

        table = new JTable(tableModel);
        table.setRowHeight(24);
        
        // Severity column dropdown
        JComboBox<String> severityCombo = new JComboBox<>(new String[]{"HIGH", "MEDIUM", "LOW", "INFO"});
        table.getColumnModel().getColumn(4).setCellEditor(new DefaultCellEditor(severityCombo));
        
        // Type column dropdown
        JComboBox<String> typeCombo = new JComboBox<>(new String[]{"SECRET", "URL", "ENDPOINT", "FILE", "INFO", "GENERIC"});
        table.getColumnModel().getColumn(3).setCellEditor(new DefaultCellEditor(typeCombo));

        // Custom renderer for regex validation coloring
        table.getColumnModel().getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                String regex = (String) value;
                String error = RegexRule.validateRegex(regex);
                if (error != null) {
                    c.setBackground(new Color(255, 200, 200));
                    setToolTipText("Invalid regex: " + error);
                } else {
                    c.setBackground(isSelected ? table.getSelectionBackground() : Color.WHITE);
                    setToolTipText(null);
                }
                return c;
            }
        });

        JScrollPane scrollPane = new JScrollPane(table);
        panel.add(scrollPane, BorderLayout.CENTER);

        // Validation label
        regexValidationLabel = new JLabel(" ");
        regexValidationLabel.setForeground(Color.RED);
        panel.add(regexValidationLabel, BorderLayout.NORTH);

        // Rule control buttons
        JPanel ruleButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addButton = new JButton("Add Rule");
        JButton deleteButton = new JButton("Delete Selected");
        JButton validateButton = new JButton("Validate All");
        JButton moveUpButton = new JButton("Move Up");
        JButton moveDownButton = new JButton("Move Down");

        addButton.addActionListener(e -> {
            tableModel.addRow(new Object[]{true, "New Rule", "", "GENERIC", "INFO"});
            table.setRowSelectionInterval(tableModel.getRowCount() - 1, tableModel.getRowCount() - 1);
        });
        
        deleteButton.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            if (selectedRow != -1) {
                tableModel.removeRow(selectedRow);
            }
        });
        
        validateButton.addActionListener(e -> {
            if (validateAllRules()) {
                regexValidationLabel.setText("All rules valid!");
                regexValidationLabel.setForeground(new Color(0, 128, 0));
            }
        });

        moveUpButton.addActionListener(e -> moveRow(-1));
        moveDownButton.addActionListener(e -> moveRow(1));

        ruleButtonPanel.add(addButton);
        ruleButtonPanel.add(deleteButton);
        ruleButtonPanel.add(validateButton);
        ruleButtonPanel.add(moveUpButton);
        ruleButtonPanel.add(moveDownButton);
        
        panel.add(ruleButtonPanel, BorderLayout.SOUTH);

        return panel;
    }

    private void moveRow(int direction) {
        int selectedRow = table.getSelectedRow();
        if (selectedRow == -1) return;
        
        int newIndex = selectedRow + direction;
        if (newIndex < 0 || newIndex >= tableModel.getRowCount()) return;

        tableModel.moveRow(selectedRow, selectedRow, newIndex);
        table.setRowSelectionInterval(newIndex, newIndex);
    }

    private boolean validateAllRules() {
        List<String> errors = new ArrayList<>();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String name = (String) tableModel.getValueAt(i, 1);
            String regex = (String) tableModel.getValueAt(i, 2);
            String error = RegexRule.validateRegex(regex);
            if (error != null) {
                errors.add("Row " + (i + 1) + " (" + name + "): " + error);
            }
        }
        
        if (!errors.isEmpty()) {
            regexValidationLabel.setText("Invalid rules: " + errors.size());
            regexValidationLabel.setForeground(Color.RED);
            JOptionPane.showMessageDialog(this, 
                "The following rules have invalid regex:\n\n" + String.join("\n", errors),
                "Validation Errors", JOptionPane.ERROR_MESSAGE);
            return false;
        }
        return true;
    }

    private void importRules() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Import Rules");
        fileChooser.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
        
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (BufferedReader reader = new BufferedReader(new FileReader(fileChooser.getSelectedFile()))) {
                Type listType = new TypeToken<ArrayList<RegexRule>>(){}.getType();
                List<RegexRule> importedRules = gson.fromJson(reader, listType);
                
                if (importedRules != null && !importedRules.isEmpty()) {
                    int choice = JOptionPane.showOptionDialog(this,
                        "Import " + importedRules.size() + " rules. What would you like to do?",
                        "Import Rules",
                        JOptionPane.YES_NO_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        null,
                        new String[]{"Replace All", "Append", "Cancel"},
                        "Append");
                    
                    if (choice == 0) { // Replace
                        rules = importedRules;
                        refreshTable();
                    } else if (choice == 1) { // Append
                        rules.addAll(importedRules);
                        refreshTable();
                    }
                }
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Failed to import rules: " + e.getMessage(),
                    "Import Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportRules() {
        // Save current table state to rules list first
        updateRulesFromTable();
        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Rules");
        fileChooser.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
        String timestamp = new SimpleDateFormat("yyyyMMdd").format(new Date());
        fileChooser.setSelectedFile(new java.io.File("jsminer_rules_" + timestamp + ".json"));
        
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            java.io.File file = fileChooser.getSelectedFile();
            if (!file.getName().endsWith(".json")) {
                file = new java.io.File(file.getAbsolutePath() + ".json");
            }
            
            try (FileWriter writer = new FileWriter(file)) {
                writer.write(gson.toJson(rules));
                JOptionPane.showMessageDialog(this, "Exported " + rules.size() + " rules to: " + file.getName(),
                    "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Failed to export rules: " + e.getMessage(),
                    "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void resetToDefaults() {
        createDefaultRules();
        mimeTypesTextArea.setText(DEFAULT_MIME_TYPES);
        noisePatternsTextArea.setText(DEFAULT_NOISE_PATTERNS);
        noiseDomainsTextArea.setText(DEFAULT_NOISE_DOMAINS);
        modulePrefixesTextArea.setText(DEFAULT_MODULE_PREFIXES);
        inScopeOnlyCheckbox.setSelected(true);
        maxFileSizeField.setText(String.valueOf(DEFAULT_MAX_FILE_SIZE_MB));
        logLevelCombo.setSelectedItem("INFO");
        refreshTable();
        saveConfig();
    }

    private void loadConfig() {
        try {
            PersistedObject prefs = api.persistence().extensionData();
            
            // Load rules
            String json = prefs.getString("jsminer_rules");
            if (json == null || json.isEmpty()) {
                createDefaultRules();
            } else {
                try {
                    Type listType = new TypeToken<ArrayList<RegexRule>>(){}.getType();
                    rules = gson.fromJson(json, listType);
                    if (rules == null) createDefaultRules();
                } catch (Exception e) {
                    extension.log(JsMinerExtension.LogLevel.WARN, "Failed to load rules, using defaults: " + e.getMessage());
                    createDefaultRules();
                }
            }

            // Load other settings
            Boolean scopeOnly = prefs.getBoolean("jsminer_scope");
            inScopeOnlyCheckbox.setSelected(scopeOnly != null ? scopeOnly : true);

            String mimeTypes = prefs.getString("jsminer_mimetypes");
            mimeTypesTextArea.setText(mimeTypes != null ? mimeTypes : DEFAULT_MIME_TYPES);

            String noisePatterns = prefs.getString("jsminer_noise");
            noisePatternsTextArea.setText(noisePatterns != null ? noisePatterns : DEFAULT_NOISE_PATTERNS);

            String noiseDomains = prefs.getString("jsminer_noise_domains");
            noiseDomainsTextArea.setText(noiseDomains != null ? noiseDomains : DEFAULT_NOISE_DOMAINS);

            String modulePrefixes = prefs.getString("jsminer_module_prefixes");
            modulePrefixesTextArea.setText(modulePrefixes != null ? modulePrefixes : DEFAULT_MODULE_PREFIXES);

            String maxFileSizeStr = prefs.getString("jsminer_max_file_size");
            maxFileSizeField.setText(maxFileSizeStr != null ? maxFileSizeStr : String.valueOf(DEFAULT_MAX_FILE_SIZE_MB));

            String logLevel = prefs.getString("jsminer_log_level");
            logLevelCombo.setSelectedItem(logLevel != null ? logLevel : "INFO");

            refreshTable();
        } catch (Exception e) {
            extension.log(JsMinerExtension.LogLevel.ERROR, "Failed to load config: " + e.getMessage());
            resetToDefaults();
        }
    }

    private void createDefaultRules() {
        rules = new ArrayList<>();
        
        // ==================== HIGH SEVERITY SECRETS ====================
        
        // Cloud Provider Keys
        rules.add(new RegexRule(true, "AWS Key ID", "(AKIA[0-9A-Z]{16})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "AWS Secret Key", "(?i)(aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"])", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Google API Key", "(AIza[0-9A-Za-z\\-_]{35})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Google OAuth ID", "([0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com)", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Firebase API Key", "(AIza[0-9A-Za-z\\-_]{35})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Firebase URL", "(https://[a-z0-9-]+\\.firebaseio\\.com)", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Firebase Realtime DB", "(https://[a-z0-9-]+\\.firebasedatabase\\.app)", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Heroku API Key", "(?i)(heroku.{0,20}['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"])", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "DigitalOcean Token", "(dop_v1_[a-f0-9]{64})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "DigitalOcean OAuth", "(doo_v1_[a-f0-9]{64})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Cloudflare API Key", "(?i)(cloudflare.{0,20}['\"][a-z0-9]{37}['\"])", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Cloudflare Token", "(v1\\.0-[a-f0-9]{24}-[a-f0-9]{146})", "SECRET", "HIGH"));
        
        // Payment/Financial
        rules.add(new RegexRule(true, "Stripe Live Key", "(sk_live_[0-9a-zA-Z]{24,})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Stripe Publishable", "(pk_live_[0-9a-zA-Z]{24,})", "SECRET", "MEDIUM"));
        rules.add(new RegexRule(true, "PayPal Client ID", "(?i)(paypal.{0,20}client.{0,10}['\"]A[a-zA-Z0-9_-]{20,}['\"])", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Square Access Token", "(sq0atp-[0-9A-Za-z\\-_]{22})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Square OAuth", "(sq0csp-[0-9A-Za-z\\-_]{43})", "SECRET", "HIGH"));
        
        // Communication APIs (SMS/Email)
        rules.add(new RegexRule(true, "Twilio Account SID", "(AC[a-z0-9]{32})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Twilio Auth Token", "(?i)(twilio.{0,20}['\"][a-f0-9]{32}['\"])", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "SendGrid API Key", "(SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Mailgun API Key", "(?i)(key-[0-9a-zA-Z]{32})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Mailchimp API Key", "([a-f0-9]{32}-us[0-9]{1,2})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Postmark Token", "(?i)(postmark.{0,20}['\"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['\"])", "SECRET", "HIGH"));
        
        // Social/Chat Platforms
        rules.add(new RegexRule(true, "Discord Webhook", "(https://discord(?:app)?\\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+)", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Discord Bot Token", "([MN][A-Za-z\\d]{23,}\\.[\\w-]{6}\\.[\\w-]{27})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Telegram Bot Token", "([0-9]+:AA[0-9A-Za-z\\-_]{33})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Slack Token", "(xox[baprs]-[0-9a-zA-Z\\-]{10,48})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Slack Webhook", "(https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)", "SECRET", "HIGH"));
        
        // Version Control
        rules.add(new RegexRule(true, "GitHub PAT", "(ghp_[0-9a-zA-Z]{36})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "GitHub OAuth", "(gho_[0-9a-zA-Z]{36})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "GitHub App Token", "(ghu_[0-9a-zA-Z]{36})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "GitHub Refresh Token", "(ghr_[0-9a-zA-Z]{36})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "GitLab Token", "(glpat-[0-9a-zA-Z\\-_]{20})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Bitbucket App Password", "(?i)(bitbucket.{0,20}['\"][a-zA-Z0-9]{32}['\"])", "SECRET", "HIGH"));
        
        // Authentication
        rules.add(new RegexRule(true, "JWT Token", "(eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]+)", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Bearer Token", "(?i)(bearer\\s+[a-zA-Z0-9_\\-\\.=]{20,})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "OAuth Access Token", "(?i)(access_token['\"]?\\s*[:=]\\s*['\"][a-zA-Z0-9_\\-\\.]{20,}['\"])", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "OAuth Refresh Token", "(?i)(refresh_token['\"]?\\s*[:=]\\s*['\"][a-zA-Z0-9_\\-\\.]{20,}['\"])", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Basic Auth Header", "(?i)(basic\\s+[a-zA-Z0-9+/=]{20,})", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Private Key", "(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)", "SECRET", "HIGH"));
        
        // Database
        rules.add(new RegexRule(true, "MongoDB URL", "(mongodb(?:\\+srv)?://[^\\s\"'<>]+)", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "PostgreSQL URL", "(postgres(?:ql)?://[^\\s\"'<>]+)", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "MySQL URL", "(mysql://[^\\s\"'<>]+)", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Redis URL", "(redis://[^\\s\"'<>]+)", "SECRET", "HIGH"));
        
        // SaaS/Analytics
        rules.add(new RegexRule(true, "Segment Write Key", "(?i)(segment.{0,20}['\"][a-zA-Z0-9]{32}['\"])", "SECRET", "MEDIUM"));
        rules.add(new RegexRule(true, "Mixpanel Token", "(?i)(mixpanel.{0,20}['\"][a-f0-9]{32}['\"])", "SECRET", "MEDIUM"));
        rules.add(new RegexRule(true, "Intercom App ID", "(?i)(intercom.{0,20}['\"][a-z0-9]{8}['\"])", "SECRET", "MEDIUM"));
        rules.add(new RegexRule(true, "Amplitude API Key", "(?i)(amplitude.{0,20}['\"][a-f0-9]{32}['\"])", "SECRET", "MEDIUM"));
        rules.add(new RegexRule(true, "Algolia API Key", "(?i)(algolia.{0,20}['\"][a-zA-Z0-9]{32}['\"])", "SECRET", "MEDIUM"));
        rules.add(new RegexRule(true, "Sentry DSN", "(https://[a-f0-9]+@[a-z0-9]+\\.ingest\\.sentry\\.io/[0-9]+)", "SECRET", "MEDIUM"));
        rules.add(new RegexRule(true, "Datadog API Key", "(?i)(datadog.{0,20}['\"][a-f0-9]{32}['\"])", "SECRET", "MEDIUM"));
        rules.add(new RegexRule(true, "New Relic Key", "(?i)(new.?relic.{0,20}['\"][A-Za-z0-9\\-_]{32,}['\"])", "SECRET", "MEDIUM"));
        
        // ==================== HARDCODED CREDENTIALS ====================
        rules.add(new RegexRule(true, "Hardcoded Password", "(?i)(['\"]?password['\"]?\\s*[:=]\\s*['\"][^'\"]{4,}['\"])", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Hardcoded Password 2", "(?i)(['\"]?passwd['\"]?\\s*[:=]\\s*['\"][^'\"]{4,}['\"])", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Hardcoded Password 3", "(?i)(['\"]?pwd['\"]?\\s*[:=]\\s*['\"][^'\"]{4,}['\"])", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Hardcoded Secret", "(?i)(['\"]?secret['\"]?\\s*[:=]\\s*['\"][^'\"]{8,}['\"])", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Generic API Key", "(?i)(['\"]?api[_-]?key['\"]?\\s*[:=]\\s*['\"][a-zA-Z0-9_\\-]{16,}['\"])", "SECRET", "MEDIUM"));
        rules.add(new RegexRule(true, "Generic Secret Key", "(?i)(['\"]?secret[_-]?key['\"]?\\s*[:=]\\s*['\"][a-zA-Z0-9_\\-]{16,}['\"])", "SECRET", "HIGH"));
        rules.add(new RegexRule(true, "Auth Token Generic", "(?i)(['\"]?auth[_-]?token['\"]?\\s*[:=]\\s*['\"][a-zA-Z0-9_\\-\\.]{16,}['\"])", "SECRET", "HIGH"));
        
        // ==================== BASE64 ENCODED SECRETS ====================
        rules.add(new RegexRule(true, "Base64 Password", "(?i)(password['\"]?\\s*[:=]\\s*['\"](?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?['\"])", "SECRET", "MEDIUM"));
        rules.add(new RegexRule(true, "Base64 Credentials", "(?i)(credentials?['\"]?\\s*[:=]\\s*['\"](?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?['\"])", "SECRET", "MEDIUM"));
        
        // ==================== INTERNAL INFRASTRUCTURE ====================
        rules.add(new RegexRule(true, "Internal IP (10.x)", "(\\b10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b)", "INFO", "MEDIUM"));
        rules.add(new RegexRule(true, "Internal IP (172.16-31)", "(\\b172\\.(?:1[6-9]|2[0-9]|3[0-1])\\.\\d{1,3}\\.\\d{1,3}\\b)", "INFO", "MEDIUM"));
        rules.add(new RegexRule(true, "Internal IP (192.168)", "(\\b192\\.168\\.\\d{1,3}\\.\\d{1,3}\\b)", "INFO", "MEDIUM"));
        rules.add(new RegexRule(true, "Internal Hostname", "(?i)(['\"](?:dev|staging|internal|corp|intranet|local)[a-zA-Z0-9.-]*\\.[a-zA-Z]{2,}['\"])", "INFO", "MEDIUM"));
        
        // ==================== DEBUG/TEST ENDPOINTS ====================
        rules.add(new RegexRule(true, "Debug Endpoint", "(?i)[\"'](/(?:debug|_debug|__debug)[a-zA-Z0-9/_-]*)[\"']", "ENDPOINT", "HIGH"));
        rules.add(new RegexRule(true, "Test Endpoint", "(?i)[\"'](/(?:test|_test|testing)[a-zA-Z0-9/_-]*)[\"']", "ENDPOINT", "MEDIUM"));
        rules.add(new RegexRule(true, "Dev Endpoint", "(?i)[\"'](/(?:dev|_dev|development)[a-zA-Z0-9/_-]*)[\"']", "ENDPOINT", "MEDIUM"));
        rules.add(new RegexRule(true, "Staging Endpoint", "(?i)[\"'](/(?:staging|stage|preprod)[a-zA-Z0-9/_-]*)[\"']", "ENDPOINT", "MEDIUM"));
        rules.add(new RegexRule(true, "Admin Endpoint", "(?i)[\"'](/(?:admin|_admin|administrator|manage|management)[a-zA-Z0-9/_-]*)[\"']", "ENDPOINT", "HIGH"));
        rules.add(new RegexRule(true, "Backup Endpoint", "(?i)[\"'](/(?:backup|backups|bak|old)[a-zA-Z0-9/_-]*)[\"']", "ENDPOINT", "MEDIUM"));
        rules.add(new RegexRule(true, "Config Endpoint", "(?i)[\"'](/(?:config|configuration|settings|setup)[a-zA-Z0-9/_-]*)[\"']", "ENDPOINT", "MEDIUM"));
        rules.add(new RegexRule(true, "PHPInfo/ServerInfo", "(?i)[\"'](/(?:phpinfo|server-?info|status|health)[a-zA-Z0-9/_.-]*)[\"']", "ENDPOINT", "HIGH"));
        
        // ==================== API ENDPOINTS ====================
        rules.add(new RegexRule(true, "Generic Path", "['\"](/[a-zA-Z0-9/._-]{10,})['\"]", "ENDPOINT", "LOW"));
        rules.add(new RegexRule(true, "API Endpoint", "(?i)[\"']((?:https?:)?//[^\"']+/api/[a-zA-Z0-9/_-]+)[\"']", "ENDPOINT", "MEDIUM"));
        rules.add(new RegexRule(true, "REST API v1/v2/v3", "(?i)[\"'](/(?:api/)?v[1-3]/[a-zA-Z0-9/_-]+)[\"']", "ENDPOINT", "MEDIUM"));
        rules.add(new RegexRule(true, "GraphQL Endpoint", "(?i)[\"'](/graphql[a-zA-Z0-9/_-]*)[\"']", "ENDPOINT", "MEDIUM"));
        
        // ==================== CLOUD STORAGE ====================
        rules.add(new RegexRule(true, "Full URL", "[\"'](https?://[^\\s\"'<>]{10,})[\"']", "URL", "LOW"));
        rules.add(new RegexRule(true, "WebSocket URL", "[\"'](wss?://[^\\s\"'<>]{10,})[\"']", "URL", "MEDIUM"));
        rules.add(new RegexRule(true, "S3 Bucket", "(https?://[a-zA-Z0-9.-]+\\.s3[a-zA-Z0-9.-]*\\.amazonaws\\.com[^\\s\"'<>']*)", "URL", "MEDIUM"));
        rules.add(new RegexRule(true, "S3 Bucket Alt", "(s3://[a-zA-Z0-9.-]+[^\\s\"'<>']*)", "URL", "MEDIUM"));
        rules.add(new RegexRule(true, "Azure Blob URL", "(https?://[a-zA-Z0-9.-]+\\.blob\\.core\\.windows\\.net[^\\s\"'<>']*)", "URL", "MEDIUM"));
        rules.add(new RegexRule(true, "GCP Storage URL", "(https?://storage\\.googleapis\\.com/[^\\s\"'<>']*)", "URL", "MEDIUM"));
        rules.add(new RegexRule(true, "GCP Storage Bucket", "(gs://[a-zA-Z0-9._-]+[^\\s\"'<>']*)", "URL", "MEDIUM"));
        
        // ==================== OTHER INFO ====================
        rules.add(new RegexRule(true, "Email Address", "([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6})", "INFO", "LOW"));
        rules.add(new RegexRule(true, "Sensitive File", "(?i)[\"']([a-zA-Z0-9_/.-]+\\.(?:sql|csv|json|xml|yml|yaml|log|conf|ini|env|bak|backup|key|pem|crt|pfx|p12|jks))[\"']", "FILE", "LOW"));
        rules.add(new RegexRule(true, "Public IP Address", "(\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b)", "INFO", "LOW"));
    }

    private void refreshTable() {
        tableModel.setRowCount(0);
        for (RegexRule rule : rules) {
            tableModel.addRow(new Object[]{
                rule.isActive(), 
                rule.getName(), 
                rule.getRegex(), 
                rule.getType(),
                rule.getSeverity()
            });
        }
    }

    private void updateRulesFromTable() {
        List<RegexRule> newRules = new ArrayList<>();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            boolean active = (boolean) tableModel.getValueAt(i, 0);
            String name = (String) tableModel.getValueAt(i, 1);
            String regex = (String) tableModel.getValueAt(i, 2);
            String type = (String) tableModel.getValueAt(i, 3);
            String severity = (String) tableModel.getValueAt(i, 4);
            newRules.add(new RegexRule(active, name, regex, type, severity));
        }
        this.rules = newRules;
    }

    public void saveConfig() {
        updateRulesFromTable();

        // Persist all settings
        PersistedObject prefs = api.persistence().extensionData();
        prefs.setString("jsminer_rules", gson.toJson(rules));
        prefs.setBoolean("jsminer_scope", inScopeOnlyCheckbox.isSelected());
        prefs.setString("jsminer_mimetypes", mimeTypesTextArea.getText());
        prefs.setString("jsminer_noise", noisePatternsTextArea.getText());
        prefs.setString("jsminer_noise_domains", noiseDomainsTextArea.getText());
        prefs.setString("jsminer_module_prefixes", modulePrefixesTextArea.getText());
        prefs.setString("jsminer_log_level", (String) logLevelCombo.getSelectedItem());
        
        // Save Max File Size
        try {
            Double.parseDouble(maxFileSizeField.getText());
            prefs.setString("jsminer_max_file_size", maxFileSizeField.getText());
        } catch (NumberFormatException e) {
            prefs.setString("jsminer_max_file_size", String.valueOf(DEFAULT_MAX_FILE_SIZE_MB));
        }
        
        // Update extension settings
        if (extension != null) {
            extension.updateNoisePatterns();
            String selectedLevel = (String) logLevelCombo.getSelectedItem();
            extension.setLogLevel(JsMinerExtension.LogLevel.valueOf(selectedLevel));
        }
    }

    // Public getters
    public List<RegexRule> getRules() { return rules; }
    public boolean isScopeOnly() { return inScopeOnlyCheckbox.isSelected(); }
    public String[] getMimeTypes() { return mimeTypesTextArea.getText().split("\n"); }
    public String[] getNoisePatterns() { return noisePatternsTextArea.getText().split("\n"); }
    
    public List<String> getNoiseDomains() {
        List<String> domains = new ArrayList<>();
        for (String domain : noiseDomainsTextArea.getText().split("\n")) {
            if (!domain.trim().isEmpty()) {
                domains.add(domain.trim());
            }
        }
        return domains;
    }
    
    public List<String> getModulePrefixes() {
        List<String> prefixes = new ArrayList<>();
        for (String prefix : modulePrefixesTextArea.getText().split("\n")) {
            if (!prefix.trim().isEmpty()) {
                prefixes.add(prefix.trim());
            }
        }
        return prefixes;
    }
    
    public double getMaxFileSizeMb() {
        try {
            return Double.parseDouble(maxFileSizeField.getText());
        } catch (NumberFormatException e) {
            return DEFAULT_MAX_FILE_SIZE_MB;
        }
    }
}