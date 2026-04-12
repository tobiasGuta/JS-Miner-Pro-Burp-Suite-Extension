package com.burp.custom.ui;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.net.URI;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Per-host statistics panel.
 * Displays a breakdown of findings grouped by hostname, type, and severity.
 * All mutation happens on the EDT through SwingUtilities.invokeLater().
 */
public class StatsTab extends JPanel {

    private final MontoyaApi api;

    // host → type → severity → count
    private final ConcurrentHashMap<String, ConcurrentHashMap<String, ConcurrentHashMap<String, AtomicInteger>>> stats
        = new ConcurrentHashMap<>();

    private final DefaultTableModel tableModel;
    private final JLabel totalLabel;

    private final AtomicInteger totalFindings   = new AtomicInteger(0);
    private final AtomicInteger totalHigh       = new AtomicInteger(0);
    private final AtomicInteger totalMedium     = new AtomicInteger(0);
    private final AtomicInteger totalLow        = new AtomicInteger(0);

    public StatsTab(MontoyaApi api) {
        this.api = api;
        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // ---- Summary bar ----
        totalLabel = new JLabel("Total: 0 findings  |  HIGH: 0  |  MEDIUM: 0  |  LOW: 0");
        totalLabel.setFont(totalLabel.getFont().deriveFont(Font.BOLD, 13f));
        totalLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        add(totalLabel, BorderLayout.NORTH);

        // ---- Per-host table ----
        String[] cols = {"Host", "Total", "HIGH", "MEDIUM", "LOW / INFO", "Top Type"};
        tableModel = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(0).setPreferredWidth(280);
        table.getColumnModel().getColumn(1).setPreferredWidth(60);
        table.getColumnModel().getColumn(2).setPreferredWidth(60);
        table.getColumnModel().getColumn(3).setPreferredWidth(70);
        table.getColumnModel().getColumn(4).setPreferredWidth(80);
        table.getColumnModel().getColumn(5).setPreferredWidth(100);

        add(new JScrollPane(table), BorderLayout.CENTER);

        // ---- Refresh button ----
        JButton refreshBtn = new JButton("Refresh");
        refreshBtn.addActionListener(e -> refreshTable());
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        btnPanel.add(refreshBtn);

        JButton clearBtn = new JButton("Clear Stats");
        clearBtn.addActionListener(e -> clearStats());
        btnPanel.add(clearBtn);

        add(btnPanel, BorderLayout.SOUTH);
    }

    /**
     * Called from the analysis thread — increments counters atomically,
     * then schedules a lightweight EDT update.
     */
    public void recordFinding(String url, String type, String severity) {
        String host = extractHost(url);

        stats.computeIfAbsent(host, h -> new ConcurrentHashMap<>())
             .computeIfAbsent(type, t -> new ConcurrentHashMap<>())
             .computeIfAbsent(severity, s -> new AtomicInteger(0))
             .incrementAndGet();

        totalFindings.incrementAndGet();
        switch (severity.toUpperCase()) {
            case "HIGH":   totalHigh.incrementAndGet();   break;
            case "MEDIUM": totalMedium.incrementAndGet(); break;
            default:       totalLow.incrementAndGet();    break;
        }

        SwingUtilities.invokeLater(this::refreshTable);
    }

    public void clearStats() {
        stats.clear();
        totalFindings.set(0);
        totalHigh.set(0);
        totalMedium.set(0);
        totalLow.set(0);
        SwingUtilities.invokeLater(this::refreshTable);
    }

    private void refreshTable() {
        tableModel.setRowCount(0);
        totalLabel.setText("Total: " + totalFindings.get() +
            " findings  |  HIGH: " + totalHigh.get() +
            "  |  MEDIUM: " + totalMedium.get() +
            "  |  LOW/INFO: " + totalLow.get());

        // Build rows sorted by total findings desc
        java.util.List<Map.Entry<String, ConcurrentHashMap<String, ConcurrentHashMap<String, AtomicInteger>>>> entries
            = new ArrayList<>(stats.entrySet());
        entries.sort((a, b) -> hostTotal(b.getValue()) - hostTotal(a.getValue()));

        for (Map.Entry<String, ConcurrentHashMap<String, ConcurrentHashMap<String, AtomicInteger>>> entry : entries) {
            String host = entry.getKey();
            ConcurrentHashMap<String, ConcurrentHashMap<String, AtomicInteger>> typeMap = entry.getValue();

            int total  = hostTotal(typeMap);
            int high   = severityTotal(typeMap, "HIGH");
            int medium = severityTotal(typeMap, "MEDIUM");
            int low    = severityTotal(typeMap, "LOW") + severityTotal(typeMap, "INFO");
            String topType = topType(typeMap);

            tableModel.addRow(new Object[]{ host, total, high, medium, low, topType });
        }
    }

    private int hostTotal(ConcurrentHashMap<String, ConcurrentHashMap<String, AtomicInteger>> typeMap) {
        return typeMap.values().stream()
            .flatMapToInt(m -> m.values().stream().mapToInt(AtomicInteger::get))
            .sum();
    }

    private int severityTotal(ConcurrentHashMap<String, ConcurrentHashMap<String, AtomicInteger>> typeMap, String severity) {
        return typeMap.values().stream()
            .mapToInt(m -> m.getOrDefault(severity, new AtomicInteger(0)).get())
            .sum();
    }

    private String topType(ConcurrentHashMap<String, ConcurrentHashMap<String, AtomicInteger>> typeMap) {
        return typeMap.entrySet().stream()
            .max(Comparator.comparingInt(e ->
                e.getValue().values().stream().mapToInt(AtomicInteger::get).sum()))
            .map(Map.Entry::getKey)
            .orElse("-");
    }

    private String extractHost(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            return (host != null) ? host : url;
        } catch (Exception e) {
            // Fall back to simple string split
            if (url.contains("://")) {
                String after = url.split("://", 2)[1];
                return after.split("[/?#]")[0];
            }
            return url;
        }
    }
}
