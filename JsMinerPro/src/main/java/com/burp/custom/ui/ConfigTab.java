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
import java.util.stream.Collectors;

public class ConfigTab extends JPanel {

    private final MontoyaApi api;
    private DefaultTableModel tableModel;
    private JTable table;
    private final Gson gson;
    // Guarded by 'this' — always access via getRules() which returns a defensive copy
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

    // HTML is intentionally excluded from defaults — it produces too much noise.
    // Users can add "text/html" manually if they want to scan HTML pages too.
    private static final String DEFAULT_MIME_TYPES =
        "script\napplication/javascript\napplication/x-javascript\ntext/javascript\n" +
        "application/json\napplication/xml\ntext/plain\napplication/wasm\n" +
        "application/x-typescript\nsourcemap\napplication/octet-stream";

    private static final String DEFAULT_NOISE_PATTERNS =
        "^\\.?\\.?/\n^[a-z]{2}(-[a-z]{2})?\\.js$\n\\.xml$\n^webpack\n^_ngcontent\n" +
        "^__webpack\n^chunk\\.\n^runtime\\.\n^polyfill";

    private static final String DEFAULT_NOISE_DOMAINS =
        "www.w3.org\nschemas.openxmlformats.org\nschemas.microsoft.com\npurl.org\n" +
        "openoffice.org\ndocs.oasis-open.org\nexample.com\ntest.com\nlocalhost\n" +
        "127.0.0.1\nnpmjs.org\ngithub.com\ncdnjs.cloudflare.com\nunpkg.com\n" +
        "cdn.jsdelivr.net\nfontawesome.com\ngoogleapis.com/ajax\ngstatic.com";

    private static final String DEFAULT_MODULE_PREFIXES =
        "./\n../\n.../\n./lib\n../lib\n./utils\n../utils\n./node_modules\n./src\n./dist\n" +
        "./vendor\n./assets\n./components\n./pages\n./views\n./store\n./router";

    private static final double DEFAULT_MAX_FILE_SIZE_MB = 2.0;

    public ConfigTab(MontoyaApi api, JsMinerExtension extension) {
        this.api       = api;
        this.extension = extension;
        this.gson      = new GsonBuilder().setPrettyPrinting().create();
        setLayout(new BorderLayout(0, 5));

        JTabbedPane configTabs = new JTabbedPane();
        configTabs.addTab("General",         createGeneralSettingsPanel());
        configTabs.addTab("Noise Filtering", createNoiseFilteringPanel());
        configTabs.addTab("Rules",           createRulesPanel());
        add(configTabs, BorderLayout.CENTER);

        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton saveBtn   = new JButton("Save & Apply");
        JButton resetBtn  = new JButton("Reset to Defaults");
        JButton importBtn = new JButton("Import Rules");
        JButton exportBtn = new JButton("Export Rules");

        saveBtn.addActionListener(e -> {
            if (validateAllRules()) {
                saveConfig();
                JOptionPane.showMessageDialog(this, "Configuration saved!", "Success", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        resetBtn.addActionListener(e -> {
            if (JOptionPane.showConfirmDialog(this, "Reset ALL settings to defaults?", "Confirm Reset",
                    JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                resetToDefaults();
            }
        });
        importBtn.addActionListener(e -> importRules());
        exportBtn.addActionListener(e -> exportRules());

        controlPanel.add(saveBtn);
        controlPanel.add(resetBtn);
        controlPanel.add(Box.createHorizontalStrut(20));
        controlPanel.add(importBtn);
        controlPanel.add(exportBtn);
        add(controlPanel, BorderLayout.SOUTH);

        loadConfig();
    }

    // -------------------------------------------------------------------------
    // Panel builders
    // -------------------------------------------------------------------------

    private JPanel createGeneralSettingsPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel grid = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        inScopeOnlyCheckbox = new JCheckBox("Only analyze in-scope traffic", true);
        grid.add(inScopeOnlyCheckbox, gbc);

        gbc.gridwidth = 1;
        gbc.gridx = 0; gbc.gridy = 1;
        grid.add(new JLabel("Max File Size (MB):"), gbc);
        gbc.gridx = 1;
        maxFileSizeField = new JTextField(String.valueOf(DEFAULT_MAX_FILE_SIZE_MB), 8);
        maxFileSizeField.setToolTipText("Files larger than this are skipped (byte-based, not char-based).");
        grid.add(maxFileSizeField, gbc);

        gbc.gridx = 0; gbc.gridy = 2;
        grid.add(new JLabel("Log Level:"), gbc);
        gbc.gridx = 1;
        logLevelCombo = new JComboBox<>(new String[]{"DEBUG", "INFO", "WARN", "ERROR"});
        logLevelCombo.setSelectedItem("INFO");
        grid.add(logLevelCombo, gbc);

        panel.add(grid, BorderLayout.NORTH);

        JPanel mimePanel = new JPanel(new BorderLayout());
        mimePanel.setBorder(BorderFactory.createTitledBorder("MIME Types to Scan (one per line) — HTML excluded by default to reduce noise"));
        mimeTypesTextArea = new JTextArea();
        mimeTypesTextArea.setRows(8);
        mimePanel.add(new JScrollPane(mimeTypesTextArea), BorderLayout.CENTER);
        panel.add(mimePanel, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createNoiseFilteringPanel() {
        JPanel panel = new JPanel(new GridLayout(2, 2, 10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel np = new JPanel(new BorderLayout());
        np.setBorder(BorderFactory.createTitledBorder("Noise Patterns (Regex, one per line)"));
        noisePatternsTextArea = new JTextArea(); noisePatternsTextArea.setRows(6);
        np.add(new JScrollPane(noisePatternsTextArea), BorderLayout.CENTER);
        panel.add(np);

        JPanel nd = new JPanel(new BorderLayout());
        nd.setBorder(BorderFactory.createTitledBorder("Noise Domains (one per line)"));
        noiseDomainsTextArea = new JTextArea(); noiseDomainsTextArea.setRows(6);
        nd.add(new JScrollPane(noiseDomainsTextArea), BorderLayout.CENTER);
        panel.add(nd);

        JPanel mp = new JPanel(new BorderLayout());
        mp.setBorder(BorderFactory.createTitledBorder("Module Prefixes to Ignore (one per line)"));
        modulePrefixesTextArea = new JTextArea(); modulePrefixesTextArea.setRows(6);
        mp.add(new JScrollPane(modulePrefixesTextArea), BorderLayout.CENTER);
        panel.add(mp);

        JPanel help = new JPanel(new BorderLayout());
        help.setBorder(BorderFactory.createTitledBorder("Help"));
        JTextArea helpText = new JTextArea(
            "Noise Patterns: Regex patterns applied to the matched value.\n\n" +
            "Noise Domains: Domains to ignore in URL/endpoint findings.\n\n" +
            "Module Prefixes: Relative import paths to ignore.\n\n" +
            "Entropy scoring: LOW-entropy SECRET matches are automatically\n" +
            "downgraded to INFO regardless of rule severity.");
        helpText.setEditable(false);
        helpText.setBackground(panel.getBackground());
        helpText.setFont(helpText.getFont().deriveFont(Font.PLAIN, 11f));
        help.add(helpText, BorderLayout.CENTER);
        panel.add(help);

        return panel;
    }

    private JPanel createRulesPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        String[] columnNames = {"Active", "Name", "Regex", "Type", "Severity"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override public Class<?> getColumnClass(int col) { return col == 0 ? Boolean.class : String.class; }
            @Override public boolean isCellEditable(int r, int c) { return true; }
        };

        table = new JTable(tableModel);
        table.setRowHeight(24);

        JComboBox<String> severityCombo = new JComboBox<>(new String[]{"HIGH", "MEDIUM", "LOW", "INFO"});
        table.getColumnModel().getColumn(4).setCellEditor(new DefaultCellEditor(severityCombo));
        JComboBox<String> typeCombo = new JComboBox<>(new String[]{"SECRET", "URL", "ENDPOINT", "FILE", "INFO", "GENERIC"});
        table.getColumnModel().getColumn(3).setCellEditor(new DefaultCellEditor(typeCombo));

        table.getColumnModel().getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean foc, int r, int c) {
                Component comp = super.getTableCellRendererComponent(t, v, sel, foc, r, c);
                String regex = (String) v;
                String err = RegexRule.validateRegex(regex);
                if (err != null) {
                    comp.setBackground(new Color(255, 200, 200));
                    setToolTipText("Invalid regex: " + err);
                } else {
                    comp.setBackground(sel ? t.getSelectionBackground() : t.getBackground());
                    setToolTipText(null);
                }
                return comp;
            }
        });

        panel.add(new JScrollPane(table), BorderLayout.CENTER);

        regexValidationLabel = new JLabel(" ");
        regexValidationLabel.setForeground(Color.RED);
        panel.add(regexValidationLabel, BorderLayout.NORTH);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addBtn      = new JButton("Add Rule");
        JButton deleteBtn   = new JButton("Delete Selected");
        JButton validateBtn = new JButton("Validate All");
        JButton upBtn       = new JButton("Move Up");
        JButton downBtn     = new JButton("Move Down");

        addBtn.addActionListener(e -> {
            tableModel.addRow(new Object[]{true, "New Rule", "", "GENERIC", "INFO"});
            table.setRowSelectionInterval(tableModel.getRowCount() - 1, tableModel.getRowCount() - 1);
        });
        deleteBtn.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row >= 0) tableModel.removeRow(row);
        });
        validateBtn.addActionListener(e -> {
            if (validateAllRules()) {
                regexValidationLabel.setText("All rules valid!");
                regexValidationLabel.setForeground(new Color(0, 128, 0));
            }
        });
        upBtn.addActionListener(e -> moveRow(-1));
        downBtn.addActionListener(e -> moveRow(1));

        btnRow.add(addBtn);
        btnRow.add(deleteBtn);
        btnRow.add(validateBtn);
        btnRow.add(upBtn);
        btnRow.add(downBtn);
        panel.add(btnRow, BorderLayout.SOUTH);

        return panel;
    }

    // -------------------------------------------------------------------------
    // Public accessors — getRules() returns a defensive copy so background
    // analysis threads cannot observe a ConcurrentModificationException.
    // -------------------------------------------------------------------------

    public synchronized List<RegexRule> getRules() {
        return new ArrayList<>(rules);
    }

    public boolean isScopeOnly()       { return inScopeOnlyCheckbox.isSelected(); }
    public String[] getMimeTypes()     { return mimeTypesTextArea.getText().split("\n"); }
    public String[] getNoisePatterns() { return noisePatternsTextArea.getText().split("\n"); }

    public List<String> getNoiseDomains() {
        return Arrays.stream(noiseDomainsTextArea.getText().split("\n"))
            .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList());
    }

    public List<String> getModulePrefixes() {
        return Arrays.stream(modulePrefixesTextArea.getText().split("\n"))
            .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList());
    }

    public double getMaxFileSizeMb() {
        try { return Double.parseDouble(maxFileSizeField.getText()); }
        catch (NumberFormatException e) { return DEFAULT_MAX_FILE_SIZE_MB; }
    }

    // -------------------------------------------------------------------------
    // Validation / helpers
    // -------------------------------------------------------------------------

    private boolean validateAllRules() {
        StringBuilder errors = new StringBuilder();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String regex = (String) tableModel.getValueAt(i, 2);
            String err   = RegexRule.validateRegex(regex);
            if (err != null) {
                errors.append("Row ").append(i + 1).append(": ").append(err).append("\n");
            }
        }
        if (errors.length() > 0) {
            regexValidationLabel.setText("Errors found — see highlighted rows.");
            regexValidationLabel.setForeground(Color.RED);
            JOptionPane.showMessageDialog(this, "Invalid regex patterns:\n" + errors,
                "Validation Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }
        return true;
    }

    private void moveRow(int direction) {
        int row = table.getSelectedRow();
        if (row < 0) return;
        int target = row + direction;
        if (target < 0 || target >= tableModel.getRowCount()) return;
        tableModel.moveRow(row, row, target);
        table.setRowSelectionInterval(target, target);
    }

    private void updateRulesFromTable() {
        List<RegexRule> newRules = new ArrayList<>();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            boolean active   = (boolean) tableModel.getValueAt(i, 0);
            String  name     = (String)  tableModel.getValueAt(i, 1);
            String  regex    = (String)  tableModel.getValueAt(i, 2);
            String  type     = (String)  tableModel.getValueAt(i, 3);
            String  severity = (String)  tableModel.getValueAt(i, 4);
            newRules.add(new RegexRule(active, name, regex, type, severity));
        }
        synchronized (this) { this.rules = newRules; }
    }

    private void refreshTable() {
        tableModel.setRowCount(0);
        synchronized (this) {
            for (RegexRule rule : rules) {
                tableModel.addRow(new Object[]{rule.isActive(), rule.getName(), rule.getRegex(), rule.getType(), rule.getSeverity()});
            }
        }
    }

    // -------------------------------------------------------------------------
    // Import / Export
    // -------------------------------------------------------------------------

    private void importRules() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (Reader r = new FileReader(chooser.getSelectedFile())) {
                Type listType = new TypeToken<ArrayList<RegexRule>>(){}.getType();
                List<RegexRule> imported = gson.fromJson(r, listType);
                if (imported != null) {
                    synchronized (this) { rules = imported; }
                    refreshTable();
                    JOptionPane.showMessageDialog(this, "Imported " + imported.size() + " rules.", "Import OK", JOptionPane.INFORMATION_MESSAGE);
                }
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Import failed: " + e.getMessage(), "Import Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportRules() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
        chooser.setSelectedFile(new File("jsminer_rules_" + new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date()) + ".json"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            if (!file.getName().endsWith(".json")) file = new File(file.getAbsolutePath() + ".json");
            updateRulesFromTable();
            try (FileWriter w = new FileWriter(file)) {
                w.write(gson.toJson(rules));
                JOptionPane.showMessageDialog(this, "Exported " + rules.size() + " rules.", "Export OK", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Config persistence
    // -------------------------------------------------------------------------

    public void saveConfig() {
        updateRulesFromTable();
        PersistedObject prefs = api.persistence().extensionData();
        synchronized (this) { prefs.setString("jsminer_rules", gson.toJson(rules)); }
        prefs.setBoolean("jsminer_scope", inScopeOnlyCheckbox.isSelected());
        prefs.setString("jsminer_mimetypes",       mimeTypesTextArea.getText());
        prefs.setString("jsminer_noise",            noisePatternsTextArea.getText());
        prefs.setString("jsminer_noise_domains",    noiseDomainsTextArea.getText());
        prefs.setString("jsminer_module_prefixes",  modulePrefixesTextArea.getText());
        prefs.setString("jsminer_log_level",        (String) logLevelCombo.getSelectedItem());
        try {
            Double.parseDouble(maxFileSizeField.getText());
            prefs.setString("jsminer_max_file_size", maxFileSizeField.getText());
        } catch (NumberFormatException e) {
            prefs.setString("jsminer_max_file_size", String.valueOf(DEFAULT_MAX_FILE_SIZE_MB));
        }
        if (extension != null) {
            extension.updateNoisePatterns();
            extension.setLogLevel(JsMinerExtension.LogLevel.valueOf((String) logLevelCombo.getSelectedItem()));
        }
    }

    private void loadConfig() {
        try {
            PersistedObject prefs = api.persistence().extensionData();
            String json = prefs.getString("jsminer_rules");
            if (json == null || json.isEmpty()) {
                createDefaultRules();
            } else {
                try {
                    Type listType = new TypeToken<ArrayList<RegexRule>>(){}.getType();
                    List<RegexRule> loaded = gson.fromJson(json, listType);
                    synchronized (this) { rules = (loaded != null) ? loaded : new ArrayList<>(); }
                    if (loaded == null) createDefaultRules();
                } catch (Exception e) {
                    extension.log(JsMinerExtension.LogLevel.WARN, "Failed to load rules, using defaults: " + e.getMessage());
                    createDefaultRules();
                }
            }

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

            String maxFileSize = prefs.getString("jsminer_max_file_size");
            maxFileSizeField.setText(maxFileSize != null ? maxFileSize : String.valueOf(DEFAULT_MAX_FILE_SIZE_MB));

            String logLevel = prefs.getString("jsminer_log_level");
            logLevelCombo.setSelectedItem(logLevel != null ? logLevel : "INFO");

            refreshTable();
        } catch (Exception e) {
            extension.log(JsMinerExtension.LogLevel.ERROR, "Failed to load config: " + e.getMessage());
            resetToDefaults();
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

    // -------------------------------------------------------------------------
    // Default rules — comprehensive modern secret coverage
    // -------------------------------------------------------------------------

    private void createDefaultRules() {
        List<RegexRule> r = new ArrayList<>();

        // ==================== CLOUD PROVIDER KEYS ====================
        r.add(new RegexRule(true, "AWS Access Key ID",          "(AKIA[0-9A-Z]{16})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "AWS Secret Key",             "(?i)(aws.{0,20}secret.{0,10}['\"][0-9a-zA-Z/+]{40}['\"])", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Google API Key",             "(AIza[0-9A-Za-z\\-_]{35})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Google OAuth Client ID",     "([0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com)", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Firebase URL",               "(https://[a-z0-9-]+\\.firebaseio\\.com)", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Firebase RTDB",              "(https://[a-z0-9-]+\\.firebasedatabase\\.app)", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Firebase Config Block",      "(?s)(apiKey\\s*:\\s*['\"]AIza[0-9A-Za-z\\-_]{35}['\"])", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Heroku API Key",             "(?i)(heroku.{0,20}['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"])", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "DigitalOcean PAT",           "(dop_v1_[a-f0-9]{64})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Cloudflare API Key",         "(?i)(cloudflare.{0,20}['\"][a-z0-9]{37}['\"])", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Azure Storage Key",          "(?i)(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{44,})", "SECRET", "HIGH"));

        // ==================== AI PLATFORM KEYS ====================
        r.add(new RegexRule(true, "OpenAI API Key",             "(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "OpenAI API Key (new fmt)",   "(sk-proj-[A-Za-z0-9_-]{48,})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Anthropic API Key",          "(sk-ant-[a-zA-Z0-9\\-_]{95,})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "HuggingFace Token",          "(hf_[A-Za-z]{34})", "SECRET", "HIGH"));

        // ==================== PAYMENT / FINANCIAL ====================
        r.add(new RegexRule(true, "Stripe Live Secret Key",     "(sk_live_[0-9a-zA-Z]{24,})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Stripe Live Publishable",    "(pk_live_[0-9a-zA-Z]{24,})", "SECRET", "MEDIUM"));
        r.add(new RegexRule(true, "Stripe Test Key",            "(sk_test_[0-9a-zA-Z]{24,})", "SECRET", "LOW"));
        r.add(new RegexRule(true, "Square Access Token",        "(sq0atp-[0-9A-Za-z\\-_]{22})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Square OAuth Token",         "(sq0csp-[0-9A-Za-z\\-_]{43})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Braintree Access Token",     "(access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32})", "SECRET", "HIGH"));

        // ==================== COMMUNICATION APIs ====================
        r.add(new RegexRule(true, "Twilio Account SID",         "(AC[a-z0-9]{32})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Twilio Auth Token",          "(?i)(twilio.{0,20}['\"][a-f0-9]{32}['\"])", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "SendGrid API Key",           "(SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Mailgun API Key",            "(key-[0-9a-zA-Z]{32})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Mailchimp API Key",          "([a-f0-9]{32}-us[0-9]{1,2})", "SECRET", "HIGH"));

        // ==================== SOCIAL / CHAT PLATFORMS ====================
        r.add(new RegexRule(true, "Slack Bot/App Token",        "(xox[baprs]-[0-9a-zA-Z\\-]{10,48})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Slack Webhook URL",          "(https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Discord Webhook",            "(https://discord(?:app)?\\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+)", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Discord Bot Token",          "([MN][A-Za-z\\d]{23,}\\.[\\w-]{6}\\.[\\w-]{27})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Telegram Bot Token",         "([0-9]{8,10}:AA[0-9A-Za-z\\-_]{33})", "SECRET", "HIGH"));

        // ==================== VERSION CONTROL TOKENS ====================
        r.add(new RegexRule(true, "GitHub Classic PAT",         "(ghp_[0-9a-zA-Z]{36})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "GitHub Fine-Grained PAT",    "(github_pat_[A-Za-z0-9_]{82})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "GitHub OAuth Token",         "(gho_[0-9a-zA-Z]{36})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "GitHub App Token",           "(ghu_[0-9a-zA-Z]{36})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "GitLab PAT",                 "(glpat-[0-9a-zA-Z\\-_]{20})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "npm Access Token",           "(npm_[A-Za-z0-9]{36})", "SECRET", "HIGH"));

        // ==================== AUTHENTICATION TOKENS ====================
        // JWT — context-anchored to avoid matching base64 image data
        r.add(new RegexRule(true, "JWT Token",
            "(?<![A-Za-z0-9+/])(eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,})(?![A-Za-z0-9+/])",
            "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Bearer Token",               "(?i)(bearer\\s+[a-zA-Z0-9_\\-\\.=]{20,})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "OAuth Access Token",         "(?i)(access_token['\"]?\\s*[:=]\\s*['\"][a-zA-Z0-9_\\-\\.]{20,}['\"])", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "OAuth Refresh Token",        "(?i)(refresh_token['\"]?\\s*[:=]\\s*['\"][a-zA-Z0-9_\\-\\.]{20,}['\"])", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Private Key Header",         "(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Basic Auth Header",          "(?i)(basic\\s+[a-zA-Z0-9+/=]{20,})", "SECRET", "HIGH"));

        // ==================== DATABASE CONNECTION STRINGS ====================
        r.add(new RegexRule(true, "MongoDB URI",                "(mongodb(?:\\+srv)?://[^\\s\"'<>{},]{8,})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "PostgreSQL URI",             "(postgres(?:ql)?://[^\\s\"'<>{},]{8,})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "MySQL URI",                  "(mysql://[^\\s\"'<>{},]{8,})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Redis URI",                  "(redis://[^\\s\"'<>{},]{8,})", "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Elasticsearch URI",          "(https?://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_@.-]+@[^\\s\"'<>]{8,}:9200)", "SECRET", "HIGH"));

        // ==================== MONITORING / ANALYTICS ====================
        r.add(new RegexRule(true, "Sentry DSN",                 "(https://[a-f0-9]{32}@[o0-9]+\\.ingest(?:\\.us)?\\.sentry\\.io/[0-9]+)", "SECRET", "MEDIUM"));
        r.add(new RegexRule(true, "Datadog API Key",            "(?i)(datadog.{0,20}['\"][a-f0-9]{32}['\"])", "SECRET", "MEDIUM"));
        r.add(new RegexRule(true, "New Relic License Key",      "(?i)(new.?relic.{0,20}['\"][A-Za-z0-9\\-_]{32,}['\"])", "SECRET", "MEDIUM"));
        r.add(new RegexRule(true, "Segment Write Key",          "(?i)(segment.{0,20}['\"][a-zA-Z0-9]{32}['\"])", "SECRET", "MEDIUM"));
        r.add(new RegexRule(true, "Algolia API Key",            "(?i)(algolia.{0,20}['\"][a-zA-Z0-9]{32}['\"])", "SECRET", "MEDIUM"));
        r.add(new RegexRule(true, "Mixpanel Token",             "(?i)(mixpanel.{0,20}['\"][a-f0-9]{32}['\"])", "SECRET", "MEDIUM"));

        // ==================== HARDCODED CREDENTIALS ====================
        // Anchored with negative lookahead to avoid placeholder strings like
        // placeholder="Enter your password" or label="Current Password:"
        r.add(new RegexRule(true, "Hardcoded Password",
            "(?i)(?<!placeholder)(?<!label)(?<!aria-label)(?<!hint)(['\"]?password['\"]?\\s*[:=]\\s*['\"][^'\"\\s]{4,}['\"])",
            "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Hardcoded Secret",
            "(?i)(?<!placeholder)(['\"]?secret['\"]?\\s*[:=]\\s*['\"][^'\"\\s]{8,}['\"])",
            "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Generic API Key",
            "(?i)(['\"]?api[_-]?key['\"]?\\s*[:=]\\s*['\"][a-zA-Z0-9_\\-]{20,}['\"])",
            "SECRET", "MEDIUM"));
        r.add(new RegexRule(true, "Generic Auth Token",
            "(?i)(['\"]?auth[_-]?token['\"]?\\s*[:=]\\s*['\"][a-zA-Z0-9_\\-\\.]{20,}['\"])",
            "SECRET", "HIGH"));
        r.add(new RegexRule(true, "Base64 Credentials",
            "(?i)(credentials?['\"]?\\s*[:=]\\s*['\"](?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?['\"])",
            "SECRET", "MEDIUM"));

        // ==================== INTERNAL INFRASTRUCTURE ====================
        r.add(new RegexRule(true, "Private IP (10.x)",          "(\\b10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b)", "INFO", "MEDIUM"));
        r.add(new RegexRule(true, "Private IP (172.16-31)",     "(\\b172\\.(?:1[6-9]|2[0-9]|3[0-1])\\.\\d{1,3}\\.\\d{1,3}\\b)", "INFO", "MEDIUM"));
        r.add(new RegexRule(true, "Private IP (192.168)",       "(\\b192\\.168\\.\\d{1,3}\\.\\d{1,3}\\b)", "INFO", "MEDIUM"));
        r.add(new RegexRule(true, "Internal Hostname",
            "(?i)(['\"](?:dev|staging|internal|corp|intranet|local)[a-zA-Z0-9.-]*\\.[a-zA-Z]{2,}['\"])",
            "INFO", "MEDIUM"));

        // ==================== SENSITIVE DEBUG/ADMIN ENDPOINTS ====================
        r.add(new RegexRule(true, "Debug Endpoint",
            "(?i)[\"'](/(?:debug|_debug|__debug|__debugger__)[a-zA-Z0-9/_-]*)[\"']",
            "ENDPOINT", "HIGH"));
        r.add(new RegexRule(true, "Admin Endpoint",
            "(?i)[\"'](/(?:admin|_admin|administrator|manage|management|backstage)[a-zA-Z0-9/_-]*)[\"']",
            "ENDPOINT", "HIGH"));
        r.add(new RegexRule(true, "PHPInfo/ServerInfo",
            "(?i)[\"'](/(?:phpinfo\\.php|server-?info|server-?status|actuator)[a-zA-Z0-9/_.-]*)[\"']",
            "ENDPOINT", "HIGH"));
        r.add(new RegexRule(true, "Swagger / OpenAPI UI",
            "(?i)[\"'](/(?:swagger(?:-ui)?|api-docs|openapi)[a-zA-Z0-9/_.-]*)[\"']",
            "ENDPOINT", "MEDIUM"));
        r.add(new RegexRule(true, "GraphQL Endpoint",
            "(?i)[\"'](/graphql[a-zA-Z0-9/_-]*)[\"']",
            "ENDPOINT", "MEDIUM"));
        r.add(new RegexRule(true, "Test/Staging Endpoint",
            "(?i)[\"'](/(?:test|_test|testing|staging|stage|preprod|sandbox)[a-zA-Z0-9/_-]*)[\"']",
            "ENDPOINT", "MEDIUM"));
        r.add(new RegexRule(true, "Config/Settings Endpoint",
            "(?i)[\"'](/(?:config|configuration|settings|setup|env|environment)[a-zA-Z0-9/_-]*)[\"']",
            "ENDPOINT", "MEDIUM"));
        r.add(new RegexRule(true, "REST API v1/v2/v3",
            "(?i)[\"'](/(?:api/)?v[1-5]/[a-zA-Z0-9/_-]+)[\"']",
            "ENDPOINT", "MEDIUM"));

        // ==================== CLOUD STORAGE URLS ====================
        r.add(new RegexRule(true, "S3 Bucket URL",
            "(https?://[a-zA-Z0-9.-]+\\.s3[a-zA-Z0-9.-]*\\.amazonaws\\.com[^\\s\"'<>']*)",
            "URL", "MEDIUM"));
        r.add(new RegexRule(true, "S3 Bucket (s3:// scheme)",
            "(s3://[a-zA-Z0-9.-]+[^\\s\"'<>']*)",
            "URL", "MEDIUM"));
        r.add(new RegexRule(true, "Azure Blob Storage",
            "(https?://[a-zA-Z0-9.-]+\\.blob\\.core\\.windows\\.net[^\\s\"'<>']*)",
            "URL", "MEDIUM"));
        r.add(new RegexRule(true, "GCP Storage URL",
            "(https?://storage\\.googleapis\\.com/[^\\s\"'<>']*)",
            "URL", "MEDIUM"));
        r.add(new RegexRule(true, "GCP Storage Bucket",
            "(gs://[a-zA-Z0-9._-]+[^\\s\"'<>']*)",
            "URL", "MEDIUM"));
        r.add(new RegexRule(true, "WebSocket URL",
            "[\"'](wss?://[^\\s\"'<>]{10,})[\"']",
            "URL", "MEDIUM"));

        // ==================== SOURCE MAP DETECTION ====================
        r.add(new RegexRule(true, "Source Map Reference",
            "(sourceMappingURL=([^\\s\"']+\\.map))",
            "FILE", "MEDIUM"));
        r.add(new RegexRule(true, "Source Map URL",
            "([\"'][^\"']+\\.js\\.map[\"'])",
            "FILE", "MEDIUM"));

        // ==================== GENERIC PATHS / URLS ====================
        r.add(new RegexRule(true, "Full URL",
            "[\"'](https?://[^\\s\"'<>]{10,})[\"']",
            "URL", "LOW"));
        r.add(new RegexRule(true, "Generic API Path (≥12 chars)",
            "['\"](/(?:api|v[1-9]|rest|service|services|endpoint)[a-zA-Z0-9/._-]{8,})['\"]",
            "ENDPOINT", "LOW"));

        // ==================== OTHER INFO ====================
        r.add(new RegexRule(true, "Email Address",
            "([a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,6})",
            "INFO", "LOW"));
        r.add(new RegexRule(true, "Sensitive File Reference",
            "(?i)[\"']([a-zA-Z0-9_/.-]+\\.(?:sql|csv|json|xml|yml|yaml|log|conf|ini|env|bak|backup|key|pem|crt|pfx|p12|jks))[\"']",
            "FILE", "LOW"));
        r.add(new RegexRule(true, "Public IP Address",
            "(\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b)",
            "INFO", "LOW"));

        synchronized (this) { this.rules = r; }
    }
}
