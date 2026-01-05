package com.burp.custom.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class ResultsTab extends JPanel {

    private final DefaultTableModel tableModel;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    private final List<FindingData> findingsData = new ArrayList<>();

    public ResultsTab(MontoyaApi api) {
        this.setLayout(new BorderLayout());

        // 1. Top Half: The Findings Table
        String[] columns = {"Type", "Finding", "Rule Name", "Source URL"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Make table read-only
            }
        };
        JTable table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);
        JScrollPane tableScroll = new JScrollPane(table);

        // 2. Bottom Half: The Editors (Side-by-Side)
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        // Create a horizontal split pane: Request (Left) | Response (Right)
        JSplitPane editorsSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestEditor.uiComponent(), responseEditor.uiComponent());
        editorsSplitPane.setResizeWeight(0.5); // 50% width for each

        // 3. Main Split Pane (Vertical): Table (Top) / Editors (Bottom)
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, editorsSplitPane);
        mainSplitPane.setResizeWeight(0.5); // 50% height for table

        // 4. Control Panel (Clear Button)
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton clearButton = new JButton("Clear Results");
        clearButton.addActionListener(e -> clearResults());
        controlPanel.add(clearButton);

        this.add(controlPanel, BorderLayout.NORTH);
        this.add(mainSplitPane, BorderLayout.CENTER);

        // 5. Selection Listener (Highlighting Logic)
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = table.getSelectedRow();
                if (viewRow != -1) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    FindingData data = findingsData.get(modelRow);

                    // Load data into editors
                    requestEditor.setRequest(data.httpRequestResponse.request());
                    responseEditor.setResponse(data.httpRequestResponse.response());

                    // Auto-highlight the finding in the Response pane (Right side)
                    responseEditor.setSearchExpression(data.findingString);
                }
            }
        });
    }

    public void addFinding(String type, String finding, String ruleName, String url, HttpRequestResponse reqResp, int start, int end) {
        SwingUtilities.invokeLater(() -> {
            tableModel.addRow(new Object[]{type, finding, ruleName, url});
            findingsData.add(new FindingData(reqResp, finding));
        });
    }

    private void clearResults() {
        SwingUtilities.invokeLater(() -> {
            tableModel.setRowCount(0);
            findingsData.clear();
            requestEditor.setRequest(null);
            responseEditor.setResponse(null);
        });
    }

    private static class FindingData {
        HttpRequestResponse httpRequestResponse;
        String findingString;

        public FindingData(HttpRequestResponse reqResp, String findingString) {
            this.httpRequestResponse = reqResp;
            this.findingString = findingString;
        }
    }
}