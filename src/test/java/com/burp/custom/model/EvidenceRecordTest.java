package com.burp.custom.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class EvidenceRecordTest {
    @Test
    void separatesIdenticalResponsesFromDifferentUrls() {
        String responseHash = EvidenceRecord.responseHash("identical bundle");

        String first = EvidenceRecord.evidenceId("GET", "https://target.example/assets/app.js", "", responseHash);
        String second = EvidenceRecord.evidenceId("GET", "https://cdn.target.example/assets/app.js", "", responseHash);

        assertNotEquals(first, second);
    }

    @Test
    void separatesDifferentRequestBodiesForTheSameResponse() {
        String responseHash = EvidenceRecord.responseHash("identical response");

        String first = EvidenceRecord.evidenceId("POST", "https://target.example/api", "first", responseHash);
        String second = EvidenceRecord.evidenceId("POST", "https://target.example/api", "second", responseHash);

        assertNotEquals(first, second);
    }

    @Test
    void acceptsNullRequestBodies() {
        assertDoesNotThrow(() -> EvidenceRecord.evidenceId("GET", "https://target.example/asset.js", null,
            EvidenceRecord.responseHash("response")));
    }
}
