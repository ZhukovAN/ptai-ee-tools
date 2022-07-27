package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import lombok.*;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Getter
@Setter
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class AbstractAiProjScanSettings {

    /**
     * Project name i.e. how it will be shown in PT AI viewer interface
     */
    @JsonProperty("ProjectName")
    protected String projectName;

    @JsonProperty("ProgrammingLanguage")
    protected ScanResult.ScanSettings.Language programmingLanguage;

    @Accessors(fluent = true)
    @RequiredArgsConstructor
    public enum ScanAppType {
        PHP("Php"),
        JAVA("Java"),
        CSHARP("CSharp"),
        CONFIGURATION("Configuration"),
        FINGERPRINT("Fingerprint"),
        PMTAINT("PmTaint"),
        BLACKBOX("BlackBox"),
        JAVASCRIPT("JavaScript");

        @Getter
        private final String value;
        private static final Map<String, ScanAppType> VALUES = new HashMap<>();

        static {
            for (ScanAppType f : values()) VALUES.put(f.value, f);
        }

        public static ScanAppType from(@NonNull final String value) {
            return VALUES.get(value);
        }
    }
    @JsonProperty("ScanAppType")
    protected String scanAppType;

    @JsonProperty("Site")
    protected String site = "http://localhost";
    @JsonProperty("IsDownloadDependencies")
    protected Boolean isDownloadDependencies;
    @JsonProperty("IsUsePublicAnalysisMethod")
    protected Boolean isUsePublicAnalysisMethod;
    @JsonProperty("CustomParameters")
    protected String customParameters;

    // Java settings
    @JsonProperty("JavaParameters")
    protected String javaParameters;
    @JsonProperty("IsUnpackUserPackages")
    protected Boolean isUnpackUserPackages;
    @JsonProperty("JavaVersion")
    protected int javaVersion = 0;
    @JsonProperty("PreprocessingTimeout")
    protected int preprocessingTimeout;

    // C# settings
    @JsonProperty("ProjectType")
    protected String projectType = "Solution";
    @JsonProperty("SolutionFile")
    protected String solutionFile;

    // PMTaint Parameters
    @JsonProperty("UseTaintAnalysis")
    protected Boolean useTaintAnalysis;
    @JsonProperty("UsePmAnalysis")
    protected Boolean usePmAnalysis;

    // YARA Rules
    @JsonProperty("UseCustomYaraRules")
    protected Boolean useCustomYaraRules;

    // BlackBox Settings
    public enum BlackBoxScanLevel {
        @JsonProperty("None")
        NONE,
        @JsonProperty("Fast")
        FAST,
        @JsonProperty("Normal")
        NORMAL,
        @JsonProperty("Full")
        FULL
    }
    @JsonProperty("Level")
    protected BlackBoxScanLevel blackBoxScanLevel;

    @JsonProperty("CustomHeaders")
    protected List<List<String>> customHeaders;

    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ProxySettings {
        @JsonProperty("IsEnabled")
        protected Boolean isEnabled;
        @JsonProperty("Host")
        protected String host;
        @JsonProperty("Port")
        protected int port;

        @AllArgsConstructor
        public enum Type {
            // 0 or HTTP, 1 or HTTPNOCONNECT, 2 or SOCKS4, 3 or SOCKS5
            HTTP(0),
            HTTPNOCONNECT(1),
            SOCKS4(2),
            SOCKS5(3);

            @JsonValue
            private final int type;
        }
        @JsonProperty("Type")
        protected Type type;
        @JsonProperty("Username")
        protected String username;
        @JsonProperty("Password")
        protected String password;
    }
    @JsonProperty("ProxySettings")
    protected ProxySettings proxySettings;

    // Autocheck
    @JsonProperty("RunAutocheckAfterScan")
    protected Boolean runAutocheckAfterScan;
    @JsonProperty("AutocheckCustomHeaders")
    protected List<List<String>> autocheckCustomHeaders;
    @JsonProperty("AutocheckProxySettings")
    protected ProxySettings autocheckProxySettings;

    public AbstractAiProjScanSettings fix() {
        if (StringUtils.isEmpty(site))
            site = "http://localhost:8080";

        log.debug("Checking aiproj settings scan types");
        List<ScanAppType> scanAppTypes = null;
        if (StringUtils.isNotEmpty(scanAppType)) {
            // Remove invalid settings and comvert remaining to case-sensitive values
            scanAppTypes = Arrays.stream(scanAppType.split("[, ]+"))
                    .map(String::trim)
                    .map(s -> {
                        for (ScanAppType t : ScanAppType.values())
                            if (t.value().equalsIgnoreCase(s)) return t.value();
                        log.warn("Invalid scanAppType in aiproj file: {}", s);
                        return null;
                    })
                    .filter(StringUtils::isNotEmpty)
                    .map(ScanAppType::from)
                    .collect(Collectors.toList());
            if (scanAppTypes.isEmpty())
                log.warn("No valid scanAppTypes are set, will use default one");
        }
        if (null == scanAppTypes || scanAppTypes.isEmpty()) {
            // No valid scanAppType defined, let's autofill it with SAST engines
            // See Messages.DataContracts.LanguageExtensions::ToScanAppType as reference
            // implementation
            if (null == scanAppTypes) scanAppTypes = new ArrayList<>();
            scanAppTypes.add(ScanAppType.CONFIGURATION);
            scanAppTypes.add(ScanAppType.FINGERPRINT);
            scanAppTypes.add(ScanAppType.PMTAINT);
            if (ScanBrief.ScanSettings.Language.JAVA == programmingLanguage)
                scanAppTypes.add(ScanAppType.JAVA);
            else if (ScanBrief.ScanSettings.Language.CSHARP == programmingLanguage)
                scanAppTypes.add(ScanAppType.CSHARP);
            else if (ScanBrief.ScanSettings.Language.PHP == programmingLanguage)
                scanAppTypes.add(ScanAppType.PHP);
            else if (ScanBrief.ScanSettings.Language.JAVASCRIPT == programmingLanguage)
                scanAppTypes.add(ScanAppType.JAVASCRIPT);
        }
        scanAppType = scanAppTypes.stream().map(ScanAppType::value).collect(Collectors.joining(", "));
        log.debug("Actual scan app types are: {}", scanAppType);

        if (scanAppTypes.contains(ScanAppType.PMTAINT)) {
            usePmAnalysis = null == usePmAnalysis || usePmAnalysis;
            useTaintAnalysis = null == useTaintAnalysis || useTaintAnalysis;
        }

        return this;
    }
}