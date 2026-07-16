package com.burp.custom.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CsvSanitizerTest {
    @Test
    void prefixesSpreadsheetFormulaCells() {
        assertEquals("'=1+1", ResultsTab.csv("=1+1"));
        assertEquals("'+SUM(A1:A2)", ResultsTab.csv("+SUM(A1:A2)"));
        assertEquals("'-10", ResultsTab.csv("-10"));
        assertEquals("'@cmd", ResultsTab.csv("@cmd"));
    }

    @Test
    void quotesAndNewlinesAreSanitized() {
        assertEquals("safe\"\" value", ResultsTab.csv("safe\" value"));
        assertEquals("line one line two", ResultsTab.csv("line one\nline two"));
    }
}
