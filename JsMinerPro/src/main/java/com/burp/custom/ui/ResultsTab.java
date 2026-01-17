package com.burp.custom.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.burp.custom.model.Finding;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ResultsTab extends JPanel {

    private final MontoyaApi api;
    private final DefaultTableModel tableModel;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final Gson gson;

    // Use the new Finding model and a Set for deduplication
    private final List<Finding> findingsList = new ArrayList<>();
    private final Set<String> uniqueFindingKeys = new HashSet<>();

    private static final String FINDINGS_KEY = "jsminer_findings";

    public ResultsTab(MontoyaApi api) {
        this.api = api;
        this.gson = new Gson();
        this.setLayout(new BorderLayout());

        // 1. Top Half: The Findings Table
        String[] columns = {"Type", "Finding", "Rule Name", "Source URL"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);
        JScrollPane tableScroll = new JScrollPane(table);

        // 2. Bottom Half: The Editors
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        JSplitPane editorsSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestEditor.uiComponent(), responseEditor.uiComponent());
        editorsSplitPane.setResizeWeight(0.5);

        // 3. Main Split Pane
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, editorsSplitPane);
        mainSplitPane.setResizeWeight(0.5);

        // 4. Control Panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton clearButton = new JButton("Clear Results");
        clearButton.addActionListener(e -> clearResults());
        controlPanel.add(clearButton);

        this.add(controlPanel, BorderLayout.NORTH);
        this.add(mainSplitPane, BorderLayout.CENTER);

        // 5. Selection Listener
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = table.getSelectedRow();
                if (viewRow != -1) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    Finding finding = findingsList.get(modelRow);

                    // Only show request/response for live findings
                    if (finding.getRequestResponse() != null) {
                        requestEditor.setRequest(finding.getRequestResponse().request());
                        responseEditor.setResponse(finding.getRequestResponse().response());
                        // Highlight the finding
                        responseEditor.setSearchExpression(finding.getFinding());
                    } else {
                        // Clear editors for persisted findings
                        requestEditor.setRequest(null);
                        responseEditor.setResponse(null);
                    }
                }
            }
        });

        // Load findings on startup
        loadFindings();
    }

    public void addFinding(String type, String finding, String ruleName, String url, HttpRequestResponse reqResp, int start, int end) {
        Finding newFinding = new Finding(type, finding, ruleName, url, reqResp, start, end);

        // Deduplication check
        if (uniqueFindingKeys.add(newFinding.getUniqueKey())) {
            SwingUtilities.invokeLater(() -> {
                findingsList.add(newFinding);
                tableModel.addRow(new Object[]{type, finding, ruleName, url});
                saveFindings(); // Persist after adding a new unique finding
            });
        }
    }

    private void clearResults() {
        SwingUtilities.invokeLater(() -> {
            tableModel.setRowCount(0);
            findingsList.clear();
            uniqueFindingKeys.clear();
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
            // Clear from persistence
            api.persistence().extensionData().deleteString(FINDINGS_KEY);
        });
    }

    private void saveFindings() {
        PersistedObject prefs = api.persistence().extensionData();
        String json = gson.toJson(findingsList);
        prefs.setString(FINDINGS_KEY, json);
    }

    private void loadFindings() {
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
                        tableModel.addRow(new Object[]{finding.getType(), finding.getFinding(), finding.getRuleName(), finding.getUrl()});
                    }
                }
            }
        }
    }
}