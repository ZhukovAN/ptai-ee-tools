package com.ptsecurity.appsec.ai.desktop.utils.xml.report.details;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.ptsecurity.appsec.ai.desktop.utils.xml.report.glossary.Glossary;
import com.ptsecurity.appsec.ai.desktop.utils.xml.report.vulnerability.AbstractInterpretationVulnerability;
import com.ptsecurity.appsec.ai.desktop.utils.xml.report.vulnerability.ConfigurationVulnerability;
import com.ptsecurity.appsec.ai.desktop.utils.xml.report.vulnerability.FingerprintVulnerability;
import com.ptsecurity.appsec.ai.desktop.utils.xml.report.vulnerability.PatternMatchingVulnerability;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;

@Getter
public class Report {
    @JsonProperty("Glossary")
    protected Glossary glossary;

    @JsonProperty("ScanInfo")
    protected ScanInfo scanInfo;

    @JacksonXmlElementWrapper(useWrapping = false)
    @JsonProperty("Vulnerability")
    protected List<AbstractInterpretationVulnerability> vulnerabilities = new ArrayList<>();
    public void setVulnerabilities(List<AbstractInterpretationVulnerability> value){
        vulnerabilities.addAll(value);
    }

    @JacksonXmlElementWrapper(useWrapping = false)
    @JsonProperty("PMVulnerability")
    protected List<PatternMatchingVulnerability> pmVulnerabilities = new ArrayList<>();
    public void setPmVulnerabilities(List<PatternMatchingVulnerability> value){
        pmVulnerabilities.addAll(value);
    }

    @JacksonXmlElementWrapper(useWrapping = false)
    @JsonProperty("ConfVulnerability")
    protected List<ConfigurationVulnerability> confVulnerabilities = new ArrayList<>();
    public void setConfVulnerabilities(List<ConfigurationVulnerability> value) {
        confVulnerabilities = value;
    }

    @JacksonXmlElementWrapper(useWrapping = false)
    @JsonProperty("FingerprintVulnerability")
    protected List<FingerprintVulnerability> fingerprintVulnerabilities = new ArrayList<>();
    public void setFingerprintVulnerabilities(List<FingerprintVulnerability> value) {
        fingerprintVulnerabilities = value;
    }

}
