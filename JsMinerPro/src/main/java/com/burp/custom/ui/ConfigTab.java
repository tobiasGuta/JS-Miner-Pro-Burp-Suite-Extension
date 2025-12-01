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

    public ConfigTab(MontoyaApi api) {
        this.api = api;
        this.gson = new Gson();
        this.setLayout(new BorderLayout());

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

        JPanel controlPanel = new JPanel();
        JButton addButton = new JButton("Add Rule");
        JButton deleteButton = new JButton("Delete Selected");
        JButton resetButton = new JButton("Reset to Defaults");
        JButton saveButton = new JButton("Save & Apply");

        controlPanel.add(addButton);
        controlPanel.add(deleteButton);
        controlPanel.add(resetButton);
        controlPanel.add(saveButton);

        // Add everything directly to the main panel
        this.add(scrollPane, BorderLayout.CENTER);
        this.add(controlPanel, BorderLayout.SOUTH);

        loadRules();

        // Button Actions
        addButton.addActionListener(e -> tableModel.addRow(new Object[]{true, "New Rule", "", "PATH"}));

        deleteButton.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            if (selectedRow != -1) tableModel.removeRow(selectedRow);
        });

        resetButton.addActionListener(e -> {
            if (JOptionPane.showConfirmDialog(this, "Reset to defaults?", "Confirm", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                createDefaultRules();
                refreshTable();
                saveRulesFromTable();
            }
        });

        saveButton.addActionListener(e -> saveRulesFromTable());
    }

    private void loadRules() {
        Preferences prefs = api.persistence().preferences();
        String json = prefs.getString("jsminer_rules");
        if (json == null || json.isEmpty()) createDefaultRules();
        else {
            Type listType = new TypeToken<ArrayList<RegexRule>>(){}.getType();
            rules = gson.fromJson(json, listType);
        }
        refreshTable();
    }

    private void createDefaultRules() {
        rules = new ArrayList<>();
        // Updated Path Regex (Broader)
        rules.add(new RegexRule(true, "Relative Paths", "(?:\"|'|`)([^\"'`\\s]{0,100}(?:\\/|http)[^\"'`\\s]{2,100})(?:\"|'|`)", "PATH"));
        rules.add(new RegexRule(true, "Generic Secrets", "(?i)((?:api_?key|access_?token|secret|password|auth|bearer)[a-z0-9_\\.\\-]*)\\s*[:=]\\s*[\"']?([a-z0-9\\-_\\.]{16,})[\"']?", "SECRET"));
    }

    private void refreshTable() {
        tableModel.setRowCount(0);
        for (RegexRule rule : rules) {
            tableModel.addRow(new Object[]{rule.isActive(), rule.getName(), rule.getRegex(), rule.getType()});
        }
    }

    public void saveRulesFromTable() {
        List<RegexRule> newRules = new ArrayList<>();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            boolean active = (boolean) tableModel.getValueAt(i, 0);
            String name = (String) tableModel.getValueAt(i, 1);
            String regex = (String) tableModel.getValueAt(i, 2);
            String type = (String) tableModel.getValueAt(i, 3);
            newRules.add(new RegexRule(active, name, regex, type));
        }
        this.rules = newRules;
        String json = gson.toJson(newRules);
        api.persistence().preferences().setString("jsminer_rules", json);
    }

    public List<RegexRule> getRules() { return rules; }
}