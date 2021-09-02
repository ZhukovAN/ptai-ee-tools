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
public class AiProjScanSettings {

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
        protected final String value;
        private static final Map<String, ScanAppType> VALUES = new HashMap<>();

        static {
            for (ScanAppType f : values()) VALUES.put(f.value, f);
        }

        public static ScanAppType from(@NonNull final String value) {
            return VALUES.get(value);
        }
    }

    /**
     * This is workaround for project creation: when AST is started using JSON files
     * it sets scan parameters in the DB. But currently there's a problem: if
     * JSON have no JavaNormalizeVersionPattern then this attribute will have null
     * value in the database. In this case PT AI viewer will show empty project settings.
     * The same case is for DisabledPatterns attribute it should be zero-length array
     * instead of null. This method fixes these missing values if those aren't defined
     */
    public AiProjScanSettings fix() {
        if (null == disabledPatterns)
            disabledPatterns = new ArrayList<>();
        if (null == javaNormalizeVersionPattern)
            javaNormalizeVersionPattern = "";
        if (StringUtils.isEmpty(site))
            site = "http://localhost:8080";

        log.debug("Checking aiproj settings scan types");
        List<ScanAppType> scanAppTypes = null;
        if (StringUtils.isNotEmpty(scanAppType)) {
            // Remove invalid settings and comvert remaining to case-sensitive values
            scanAppTypes = Arrays.stream(scanAppType.split("[, ]+"))
                    .map(String::trim)
                    .map(s -> {
                        for (AiProjScanSettings.ScanAppType t : AiProjScanSettings.ScanAppType.values())
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
            scanAppTypes.add(AiProjScanSettings.ScanAppType.CONFIGURATION);
            scanAppTypes.add(AiProjScanSettings.ScanAppType.FINGERPRINT);
            scanAppTypes.add(AiProjScanSettings.ScanAppType.PMTAINT);
            if (ScanBrief.ScanSettings.Language.JAVA == programmingLanguage)
                scanAppTypes.add(AiProjScanSettings.ScanAppType.JAVA);
            else if (ScanBrief.ScanSettings.Language.CSHARP == programmingLanguage)
                scanAppTypes.add(AiProjScanSettings.ScanAppType.CSHARP);
            else if (ScanBrief.ScanSettings.Language.PHP == programmingLanguage)
                scanAppTypes.add(AiProjScanSettings.ScanAppType.PHP);
            else if (ScanBrief.ScanSettings.Language.JS == programmingLanguage)
                scanAppTypes.add(AiProjScanSettings.ScanAppType.JAVASCRIPT);
        }
        scanAppType = String.join(", ", scanAppTypes.stream().map(ScanAppType::value).collect(Collectors.toList()));
        log.debug("Actual scan app types are: {}", scanAppType);

        isUseEntryAnalysisPoint = null == isUseEntryAnalysisPoint || isUseEntryAnalysisPoint;
        useIncrementalScan = null == useIncrementalScan || useIncrementalScan;
        if (scanAppTypes.contains(ScanAppType.PMTAINT)) {
            usePmAnalysis = null == usePmAnalysis || usePmAnalysis;
            useTaintAnalysis = null == useTaintAnalysis || useTaintAnalysis;
        }

        return this;
    }

    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class EmailSettings {
        @JsonProperty("SmtpServerAddress")
        protected String smtpServerAddress;
        @JsonProperty("UserName")
        protected String userName;
        @JsonProperty("Password")
        protected String password;
        @JsonProperty("EmailRecipients")
        protected String emailRecipients;
        @JsonProperty("EnableSsl")
        protected Boolean enableSsl;
        @JsonProperty("Subject")
        protected String subject;
        @JsonProperty("ConsiderCertificateError")
        protected Boolean considerCertificateError;
        @JsonProperty("SenderEmail")
        protected String senderEmail;
    }
    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Authentication {
        @JsonProperty("auth_item")
        protected AuthItem authItem;
    }

    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AuthItem {
        @JsonProperty("domain")
        protected String domain;
        @JsonProperty("credentials")
        protected Credentials credentials;
        @JsonProperty("test_url")
        protected String testUrl;
        @JsonProperty("form_url")
        protected String formUrl;
        @JsonProperty("form_xpath")
        protected String formXPath;
        @JsonProperty("regexp_of_success")
        protected String regexpOfSuccess;
    }

    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Credentials {
        @JsonProperty("cookie")
        protected String cookie;
        @JsonProperty("type")
        protected CredentialsType type;
        @JsonProperty("login")
        protected Login login;
        @JsonProperty("password")
        protected Password password;
    }
    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Login {
        @JsonProperty("name")
        protected String name;
        @JsonProperty("value")
        protected String value;
        @JsonProperty("regexp")
        protected String regexp;
        @JsonProperty("is_regexp")
        protected Boolean regexpUsed;
    }
    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Password {
        @JsonProperty("name")
        protected String name;
        @JsonProperty("value")
        protected String value;
        @JsonProperty("regexp")
        protected String regexp;
        @JsonProperty("is_regexp")
        protected Boolean regexpUsed;
    }
    @AllArgsConstructor
    public enum CredentialsType {
        // 0 = Form, 1 = HTTP, 2 = None, 3 = Cookie
        FORM(0),
        HTTP(1),
        NONE(2),
        COOKIE(3);

        @JsonValue
        protected final int type;
    }
    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ProxySettings {
        @JsonProperty("IsEnabled")
        protected Boolean isEnabled;
        @JsonProperty("Host")
        protected String host;
        @JsonProperty("Port")
        protected int port;
        @JsonProperty("Type")
        protected ProxyType type;
        @JsonProperty("Username")
        protected String username;
        @JsonProperty("Password")
        protected String password;
    }
    @AllArgsConstructor
    public enum ProxyType {
        // 0 or HTTP, 1 or HTTPNOCONNECT, 2 or SOCKS4, 3 or SOCKS5
        HTTP(0),
        HTTPNOCONNECT(1),
        SOCKS4(2),
        SOCKS5(3);

        @JsonValue
        protected final int type;
    }
    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ReportParameters {
        @JsonProperty("SaveAsPath")
        protected String saveAsPath;
        @JsonProperty("UseElectronicSignature")
        protected Boolean useElectronicSignature;
        @JsonProperty("CertificatePath")
        protected String certificatePath;
        @JsonProperty("Password")
        protected String password;
        @JsonProperty("ShowSignatureTime")
        protected Boolean showSignatureTime;
        @JsonProperty("SignatureReason")
        protected String signatureReason;
        @JsonProperty("Location")
        protected String location;
        @JsonProperty("DoSignatureVisible")
        protected Boolean doSignatureVisible;
        @JsonProperty("IncludeDiscardedVulnerabilities")
        protected Boolean includeDiscardedVulnerabilities;
        @JsonProperty("IncludeSuppressedVulnerabilities")
        protected Boolean includeSuppressedVulnerabilities;
        @JsonProperty("IncludeSuspectedVulnerabilities")
        protected Boolean includeSuspectedVulnerabilities;
        @JsonProperty("IncludeGlossary")
        protected Boolean includeGlossary;
        @JsonProperty("ConverHtmlToPdf")
        protected Boolean converHtmlToPdf;
        @JsonProperty("RemoveHtml")
        protected Boolean removeHtml;
        @JsonProperty("CreatePdfPrintVersion")
        protected Boolean createPdfPrintVersion;
        @JsonProperty("MakeAFReport")
        protected Boolean makeAFReport;
        @JsonProperty("IncludeDFD")
        protected Boolean includeDFD;
    }

    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AutocheckAuthentication {
        @JsonProperty("auth_item")
        protected AuthItem AuthItem;
    }

    public static enum BlackBoxScanLevel {
        @JsonProperty("None")
        NONE,
        @JsonProperty("Fast")
        FAST,
        @JsonProperty("Normal")
        NORMAL,
        @JsonProperty("Full")
        FULL
    }

    // Main settings
    /**
     * Project name i.e. how it will be shown in PT AI viewer interface
     */
    @JsonProperty("ProjectName")
    protected String projectName;
    @JsonProperty("ProgrammingLanguage")
    protected ScanResult.ScanSettings.Language programmingLanguage;
    @JsonProperty("ScanAppType")
    protected String scanAppType;

    @JsonProperty("Site")
    protected String site = "http://localhost";
    @JsonProperty("IsDownloadDependencies")
    protected Boolean isDownloadDependencies;

    @JsonProperty("IsUsePublicAnalysisMethod")
    protected Boolean isUsePublicAnalysisMethod;
    @JsonProperty("IsUseEntryAnalysisPoint")
    protected Boolean isUseEntryAnalysisPoint;

    @JsonProperty("ScanUnitTimeout")
    protected long scanUnitTimeout;
    @JsonProperty("PreprocessingTimeout")
    protected int preprocessingTimeout;
    @JsonProperty("CustomParameters")
    protected String customParameters;

    @JsonProperty("SkipFileFormats")
    protected List<String> skipFileFormats;
    @JsonProperty("SkipFilesFolders")
    protected List<String> skipFilesFolders;

    // Vulnerabilities to find
    @JsonProperty("DisabledPatterns")
    protected List<String> disabledPatterns;
    @JsonProperty("DisabledTypes")
    protected List<String> disabledTypes;

    @JsonProperty("UseIncrementalScan")
    protected Boolean useIncrementalScan;
    @JsonProperty("FullRescanOnNewFilesAdded")
    protected Boolean fullRescanOnNewFilesAdded;

    @JsonProperty("ConsiderPreviousScan")
    protected Boolean considerPreviousScan;
    @JsonProperty("HideSuspectedVulnerabilities")
    protected Boolean hideSuspectedVulnerabilities;
    @JsonProperty("UseIssueTrackerIntegration")
    protected Boolean useIssueTrackerIntegration;

    // Java settings
    @JsonProperty("IsUnpackUserPackages")
    protected Boolean isUnpackUserPackages;
    @JsonProperty("JavaParameters")
    protected String javaParameters;
    @JsonProperty("JavaVersion")
    protected int javaVersion = 0;
    @JsonProperty("UseJavaNormalizeVersionPattern")
    protected Boolean useJavaNormalizeVersionPattern;
    @JsonProperty("JavaNormalizeVersionPattern")
    protected String javaNormalizeVersionPattern = "-\\d+(\\.\\d+)*";

    // C# settings
    @JsonProperty("ProjectType")
    protected String projectType = "Solution";
    @JsonProperty("SolutionFile")
    protected String solutionFile;
    @JsonProperty("WebSiteFolder")
    protected String webSiteFolder;

    // JavaScript settings
    @JsonProperty("JavaScriptProjectFile")
    protected String javaScriptProjectFile;
    @JsonProperty("JavaScriptProjectFolder")
    protected String javaScriptProjectFolder;

    // PMTaint Parameters
    @JsonProperty("UseTaintAnalysis")
    protected Boolean useTaintAnalysis;
    @JsonProperty("UsePmAnalysis")
    protected Boolean usePmAnalysis;
    @JsonProperty("DisableInterpretCores")
    protected Boolean disableInterpretCores;

    // YARA Rules
    @JsonProperty("UseDefaultFingerprints")
    protected Boolean useDefaultFingerprints;
    @JsonProperty("UseCustomYaraRules")
    protected Boolean useCustomYaraRules;

    // BlackBox Settings
    @JsonProperty("Level")
    protected BlackBoxScanLevel blackBoxScanLevel;
    @JsonProperty("CustomHeaders")
    protected List<List<String>> customHeaders;
    @JsonProperty("Authentication")
    protected Authentication authentication;

    @JsonProperty("ProxySettings")
    protected ProxySettings proxySettings;

    // Autocheck
    @JsonProperty("RunAutocheckAfterScan")
    protected Boolean runAutocheckAfterScan;
    @JsonProperty("AutocheckSite")
    protected String autocheckSite;
    @JsonProperty("AutocheckCustomHeaders")
    protected List<List<String>> autocheckCustomHeaders;
    @JsonProperty("AutocheckAuthentication")
    protected Authentication autocheckAuthentication;
    @JsonProperty("AutocheckProxySettings")
    protected ProxySettings autocheckProxySettings;

    @JsonProperty("SendEmailWithReportsAfterScan")
    protected Boolean sendEmailWithReportsAfterScan;
    @JsonProperty("CompressReport")
    protected Boolean compressReport;

    // Email Settings
    @JsonProperty("EmailSettings")
    protected EmailSettings emailSettings;

    // Report Settings
    @JsonProperty("ReportParameters")
    protected ReportParameters reportParameters;
}
