package com.ptsecurity.appsec.ai.desktop.utils.report.generator.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.collections4.CollectionUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Getter
public class Report {
    @JacksonXmlElementWrapper(useWrapping = false)
    @JsonProperty("Vulnerability")
    List<Vulnerability> vulnerabilities = new ArrayList<>();
    public void setVulnerabilities(List<Vulnerability> value){
        vulnerabilities.addAll(value);
    }

    @JacksonXmlElementWrapper(useWrapping = false)
    @JsonProperty("PMVulnerability")
    List<PMVulnerability> pmVulnerabilities = new ArrayList<>();
    public void setPmVulnerabilities(List<PMVulnerability> value){
        pmVulnerabilities.addAll(value);
    }

    @JacksonXmlElementWrapper(useWrapping = false)
    @JsonProperty("ConfVulnerability")
    List<ConfVulnerability> confVulnerabilities = new ArrayList<>();
    public void setConfVulnerabilities(List<ConfVulnerability> value) { confVulnerabilities = value; }

    @JacksonXmlElementWrapper(useWrapping = false)
    @JsonProperty("FingerprintVulnerability")
    List<FingerprintVulnerability> fingerprintVulnerabilities = new ArrayList<>();
    public void setFingerprintVulnerabilities(List<FingerprintVulnerability> value) { fingerprintVulnerabilities = value; }

    @JsonProperty("Glossary")
    Glossary glossary;

    static Map<String, GlossaryItem> glossaryIdx = new HashMap<>();

    static {

    }

    public void process() {
        if ((null != glossary) && CollectionUtils.isNotEmpty(glossary.type)) {
            for (GlossaryItem item : glossary.type) {
                if (glossaryIdx.containsKey(item.getTypeId())) continue;
                glossaryIdx.put(item.getTypeId(), item);
            }
        }

        for (Vulnerability v : vulnerabilities) {
            if (!glossaryIdx.containsKey(v.getType().getId())) continue;
            v.setGlossary(glossaryIdx.get(v.getType().getId()));
        }
        for (PMVulnerability v : pmVulnerabilities) {
            if (!glossaryIdx.containsKey(v.getType().getId())) continue;
            v.setGlossary(glossaryIdx.get(v.getType().getId()));
        }
        for (ConfVulnerability v : confVulnerabilities) {
            if (!glossaryIdx.containsKey(v.getType().getId())) continue;
            v.setGlossary(glossaryIdx.get(v.getType().getId()));
        }
        for (FingerprintVulnerability v : fingerprintVulnerabilities) {
            if (!glossaryIdx.containsKey(v.getType().getId())) continue;
            v.setGlossary(glossaryIdx.get(v.getType().getId()));
        }
    }
}
