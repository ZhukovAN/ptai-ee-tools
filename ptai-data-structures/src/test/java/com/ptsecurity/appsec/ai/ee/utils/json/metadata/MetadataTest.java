package com.ptsecurity.appsec.ai.ee.utils.json.metadata;

import com.ptsecurity.appsec.ai.ee.utils.json.metadata.description.Description;
import com.ptsecurity.appsec.ai.ee.utils.json.metadata.description.LocalizedDescription;
import com.ptsecurity.appsec.ai.ee.utils.json.metadata.issue.GenericIssueMetadata;
import com.ptsecurity.appsec.ai.ee.utils.json.metadata.issue.PatternMatchingIssueMetadata;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static com.ptsecurity.appsec.ai.ee.utils.json.metadata.description.LocalizedDescription.RU;

@DisplayName("Check PT AI Enterprise metadata helper")
class MetadataTest {

    @Test
    @DisplayName("Enumerate PM issues")
    void enumeratePmIssues() {
        for (Map.Entry<String, GenericIssueMetadata> meta : Metadata.ISSUES.entrySet()) {
            if (meta.getValue() instanceof PatternMatchingIssueMetadata) {
                PatternMatchingIssueMetadata pm = (PatternMatchingIssueMetadata) meta.getValue();
                Description description = Metadata.DESCRIPTIONS.get(pm.getKey());
                LocalizedDescription localizedDescription = description.getValues().get(RU);
            }
        }
    }
}