package com.ptsecurity.appsec.ai.ee.utils.json;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.List;

@Getter @Setter
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScanSettings {

    public enum ScanAppType {
        Php, Java, CSharp, Configuration, Fingerprint, PmTaint , BlackBox, JavaScript
    }

    /**
     * This is workaround for project creation: when AST is started using JSON files
     * it sets scan parameters in the DB. But currently there's a problem: if
     * JSON have no JavaNormalizeVersionPattern then this attribute will have null
     * value in the database. In this case PT AI viewer will show empty project settings.
     * The same case is for DisabledPatterns attribute it should be zero-length array
     * instead of null. This method fixes these missing values if those aren't defined
     */
    public ScanSettings fix() {
        if (null == disabledPatterns)
            disabledPatterns = new ArrayList<>();
        if (null == javaNormalizeVersionPattern)
            javaNormalizeVersionPattern = "";
        if (StringUtils.isEmpty(site))
            site = "http://localhost:8080";
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
        protected boolean enableSsl;
        @JsonProperty("Subject")
        protected String subject;
        @JsonProperty("ConsiderCertificateError")
        protected boolean considerCertificateError;
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
        protected boolean regexpUsed;
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
        protected boolean regexpUsed;
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
        protected boolean isEnabled;
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
        protected boolean useElectronicSignature;
        @JsonProperty("CertificatePath")
        protected String certificatePath;
        @JsonProperty("Password")
        protected String password;
        @JsonProperty("ShowSignatureTime")
        protected boolean showSignatureTime;
        @JsonProperty("SignatureReason")
        protected String signatureReason;
        @JsonProperty("Location")
        protected String location;
        @JsonProperty("DoSignatureVisible")
        protected boolean doSignatureVisible;
        @JsonProperty("IncludeDiscardedVulnerabilities")
        protected boolean includeDiscardedVulnerabilities;
        @JsonProperty("IncludeSuppressedVulnerabilities")
        protected boolean includeSuppressedVulnerabilities;
        @JsonProperty("IncludeSuspectedVulnerabilities")
        protected boolean includeSuspectedVulnerabilities;
        @JsonProperty("IncludeGlossary")
        protected boolean includeGlossary;
        @JsonProperty("ConverHtmlToPdf")
        protected boolean converHtmlToPdf;
        @JsonProperty("RemoveHtml")
        protected boolean removeHtml;
        @JsonProperty("CreatePdfPrintVersion")
        protected boolean createPdfPrintVersion;
        @JsonProperty("MakeAFReport")
        protected boolean makeAFReport;
        @JsonProperty("IncludeDFD")
        protected boolean includeDFD;
    }

    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AutocheckAuthentication {
        @JsonProperty("auth_item")
        protected AuthItem AuthItem;
    }

    public static enum ProgrammingLanguage {
        @JsonProperty("Java")
        JAVA,
        @JsonProperty("Php")
        PHP,
        @JsonProperty("Csharp")
        CSHARP,
        @JsonProperty("Vb")
        VB,
        @JsonProperty("ObjectiveC")
        OBJECTIVEC,
        @JsonProperty("CPlusPlus")
        CPLUSPLUS,
        @JsonProperty("Sql")
        SQL,
        @JsonProperty("Swift")
        SWIFT,
        @JsonProperty("Python")
        PYTHON,
        @JsonProperty("JavaScript")
        JAVASCRIPT,
        @JsonProperty("Kotlin")
        KOTLIN,
        @JsonProperty("Go")
        GO
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
    @JsonProperty("ProjectName")
    protected String projectName;
    @JsonProperty("ProgrammingLanguage")
    protected ProgrammingLanguage programmingLanguage;
    @JsonProperty("ScanAppType")
    protected String scanAppType;

    @JsonProperty("ThreadCount")
    protected int threadCount = 1;
    @JsonProperty("Site")
    protected String site = "http://localhost";
    @JsonProperty("IsDownloadDependencies")
    protected boolean isDownloadDependencies = true;

    @JsonProperty("IsUsePublicAnalysisMethod")
    protected boolean isUsePublicAnalysisMethod = false;
    @JsonProperty("IsUseEntryAnalysisPoint")
    protected boolean isUseEntryAnalysisPoint = true;

    @JsonProperty("ScanUnitTimeout")
    protected long scanUnitTimeout = 600;
    @JsonProperty("PreprocessingTimeout")
    protected int preprocessingTimeout = 60;
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
    protected boolean useIncrementalScan = true;
    @JsonProperty("FullRescanOnNewFilesAdded")
    protected boolean fullRescanOnNewFilesAdded = true;

    @JsonProperty("ConsiderPreviousScan")
    protected boolean considerPreviousScan = true;
    @JsonProperty("HideSuspectedVulnerabilities")
    protected boolean hideSuspectedVulnerabilities = true;
    @JsonProperty("UseIssueTrackerIntegration")
    protected boolean useIssueTrackerIntegration = true;

    // Java settings
    @JsonProperty("IsUnpackUserPackages")
    protected boolean isUnpackUserPackages = false;
    @JsonProperty("JavaParameters")
    protected String javaParameters;
    @JsonProperty("JavaVersion")
    protected int javaVersion = 0;
    @JsonProperty("UseJavaNormalizeVersionPattern")
    protected boolean useJavaNormalizeVersionPattern = true;
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
    protected boolean useTaintAnalysis;
    @JsonProperty("UsePmAnalysis")
    protected boolean usePmAnalysis;
    @JsonProperty("DisableInterpretCores")
    protected boolean disableInterpretCores;

    // YARA Rules
    @JsonProperty("UseDefaultFingerprints")
    protected boolean useDefaultFingerprints;
    @JsonProperty("UseCustomYaraRules")
    protected boolean useCustomYaraRules;

    // BlackBox Settings
    @JsonProperty("BlackBoxScanLevel")
    protected BlackBoxScanLevel blackBoxScanLevel;
    @JsonProperty("CustomHeaders")
    protected List<List<String>> customHeaders;
    @JsonProperty("Authentication")
    protected Authentication authentication;

    @JsonProperty("ProxySettings")
    protected ProxySettings proxySettings;

    // Autocheck
    @JsonProperty("RunAutocheckAfterScan")
    protected boolean runAutocheckAfterScan;
    @JsonProperty("AutocheckSite")
    protected String autocheckSite;
    @JsonProperty("AutocheckCustomHeaders")
    protected List<List<String>> autocheckCustomHeaders;
    @JsonProperty("AutocheckAuthentication")
    protected Authentication autocheckAuthentication;
    @JsonProperty("AutocheckProxySettings")
    protected ProxySettings autocheckProxySettings;

    @JsonProperty("SendEmailWithReportsAfterScan")
    protected boolean sendEmailWithReportsAfterScan;
    @JsonProperty("CompressReport")
    protected boolean compressReport;

    // Email Settings
    @JsonProperty("EmailSettings")
    protected EmailSettings emailSettings;

    // Report Settings
    @JsonProperty("ReportParameters")
    protected ReportParameters reportParameters;
}
