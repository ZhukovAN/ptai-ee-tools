package com.ptsecurity.appsec.ai.ee.utils.json.metadata;

import com.ptsecurity.appsec.ai.ee.utils.json.metadata.description.Description;
import com.ptsecurity.appsec.ai.ee.utils.json.metadata.description.LocalizedDescription;
import com.ptsecurity.appsec.ai.ee.utils.json.metadata.issue.GenericIssueMetadata;
import com.ptsecurity.appsec.ai.ee.utils.json.metadata.issue.PatternMatchingIssueMetadata;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;

import static com.ptsecurity.appsec.ai.ee.utils.json.metadata.description.LocalizedDescription.RU;

class MetadataTest {

    @Test
    void testMetadata() throws IOException {
        for (Map.Entry<String, GenericIssueMetadata> meta : Metadata.ISSUES.entrySet()) {
            if (meta.getValue() instanceof PatternMatchingIssueMetadata) {
                PatternMatchingIssueMetadata pm = (PatternMatchingIssueMetadata) meta.getValue();
                Description description = Metadata.DESCRIPTIONS.get(pm.getKey());
                LocalizedDescription localizedDescription = description.getValues().get(RU);
                System.out.println(localizedDescription.getHeader());
            }
        }
    }
}