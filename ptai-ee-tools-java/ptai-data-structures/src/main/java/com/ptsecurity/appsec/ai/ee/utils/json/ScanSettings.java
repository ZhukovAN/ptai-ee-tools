package com.ptsecurity.appsec.ai.ee.utils.json;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScanSettings {
    /**
     * This is workaround for project creation: when AST is started using JSON files
     * it sets scan parameters in the DB. But currently there's a problem: if
     * JSON have no JavaNormalizeVersionPattern then this attribute will have null
     * value in the database. In this case PT AI viewer will show empty project settings.
     * The same case is for DisabledPatterns attribute it should be zero-length array
     * instead of null. This method fixes these missing values if those aren't defined
     */
    public ScanSettings fix() {
        if (null == disabledPatterns) disabledPatterns = new String[0];
        if (null == javaNormalizeVersionPattern) javaNormalizeVersionPattern = "";
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
        @Getter
        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class auth_item {
            @Getter
            @JsonIgnoreProperties(ignoreUnknown = true)
            public static class credentials {
                @Getter
                @JsonIgnoreProperties(ignoreUnknown = true)
                public static class login {
                    @JsonProperty("name")
                    protected String name;
                    @JsonProperty("value")
                    protected String value;
                    @JsonProperty("regexp")
                    protected String regexp;
                    @JsonProperty("is_regexp")
                    protected boolean is_regexp;
                }
                @Getter
                @JsonIgnoreProperties(ignoreUnknown = true)
                public static class password {
                    @JsonProperty("name")
                    protected String name;
                    @JsonProperty("value")
                    protected String value;
                    @JsonProperty("regexp")
                    protected String regexp;
                    @JsonProperty("is_regexp")
                    protected boolean is_regexp;
                }
                @JsonProperty("cookie")
                protected String cookie;
                @JsonProperty("type")
                protected int type;
                @JsonProperty("login")
                protected login login;
                @JsonProperty("password")
                protected password password;
            }
            @JsonProperty("domain")
            protected String domain;
            @JsonProperty("credentials")
            protected credentials credentials;
            @JsonProperty("test_url")
            protected String test_url;
            @JsonProperty("form_url")
            protected String form_url;
            @JsonProperty("form_xpath")
            protected String form_xpath;
            @JsonProperty("regexp_of_success")
            protected String regexp_of_success;
        }
        @JsonProperty("auth_item")
        protected auth_item auth_item;
    }

    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ProxySettings {
        @JsonProperty("IsEnabled")
        protected boolean isEnabled;
        @JsonProperty("Host")
        protected String host;
        @JsonProperty("Port")
        protected String port;
        @JsonProperty("Type")
        protected String type;
        @JsonProperty("Username")
        protected String username;
        @JsonProperty("Password")
        protected String password;
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
        protected ScanSettings.Authentication.auth_item auth_item;
    }

    // Main settings
    @JsonProperty("ProjectName")
    protected String projectName;
    @JsonProperty("ProgrammingLanguage")
    protected String programmingLanguage;
    @JsonProperty("ScanAppType")
    protected String scanAppType;
    @JsonProperty("ThreadCount")
    protected int threadCount;
    @JsonProperty("Site")
    protected String site;
    @JsonProperty("IsDownloadDependencies")
    protected boolean isDownloadDependencies;
    @JsonProperty("IsUsePublicAnalysisMethod")
    protected boolean isUsePublicAnalysisMethod;
    @JsonProperty("IsUseEntryAnalysisPoint")
    protected boolean isUseEntryAnalysisPoint;
    @JsonProperty("IsGraphEnabled")
    protected boolean isGraphEnabled;
    @JsonProperty("UseIncrementalScan")
    protected boolean useIncrementalScan;
    @JsonProperty("ScanUnitTimeout")
    protected int scanUnitTimeout;
    @JsonProperty("PreprocessingTimeout")
    protected int preprocessingTimeout;
    @JsonProperty("RunAutocheckAfterScan")
    protected boolean runAutocheckAfterScan;
    @JsonProperty("CustomParameters")
    protected String customParameters;
    @JsonProperty("SkipFileFormats")
    protected String[] skipFileFormats;
    @JsonProperty("SkipFilesFolders")
    protected String[] skipFilesFolders;
    @JsonProperty("UseIssueTrackerIntegration")
    protected boolean useIssueTrackerIntegration;

    // Java settings
    @JsonProperty("IsUnpackUserPackages")
    protected boolean isUnpackUserPackages;
    @JsonProperty("JavaParameters")
    protected String javaParameters;
    @JsonProperty("JavaVersion")
    protected int javaVersion;
    @JsonProperty("UseJavaNormalizeVersionPattern")
    protected String useJavaNormalizeVersionPattern;
    @JsonProperty("JavaNormalizeVersionPattern")
    protected String javaNormalizeVersionPattern;

    // C# settings
    @JsonProperty("ProjectType")
    protected String projectType;
    @JsonProperty("SolutionFile")
    protected String solutionFile;
    @JsonProperty("WebSiteFolder")
    protected String webSiteFolder;

    // JavaScript settings
    @JsonProperty("JavaScriptProjectFile")
    protected String javaScriptProjectFile;

    // Vulnerabilities to find
    @JsonProperty("DisabledPatterns")
    protected String[] disabledPatterns;
    @JsonProperty("DisabledTypes")
    protected String[] disabledTypes;

    // YARA Rules
    @JsonProperty("UseDefaultFingerprints")
    protected boolean useDefaultFingerprints;
    @JsonProperty("UseCustomYaraRules")
    protected boolean useCustomYaraRules;

    @JsonProperty("SendEmailWithReportsAfterScan")
    protected boolean sendEmailWithReportsAfterScan;
    @JsonProperty("CompressReport")
    protected boolean compressReport;

    // Email Settings
    @JsonProperty("EmailSettings")
    protected EmailSettings emailSettings;

    // BlackBox Settings
    @JsonProperty("Level")
    protected String level;
    @JsonProperty("CustomHeaders")
    protected String[][] customHeaders;
    @JsonProperty("Authentication")
    protected Authentication authentication;

    @JsonProperty("ProxySettings")
    protected ProxySettings proxySettings;
    @JsonProperty("ReportParameters")
    protected ReportParameters reportParameters;

    // Autocheck
    @JsonProperty("AutocheckSite")
    protected String autocheckSite;
    @JsonProperty("AutocheckCustomHeaders")
    protected String[][] autocheckCustomHeaders;
    @JsonProperty("AutocheckAuthentication")
    protected Authentication autocheckAuthentication;
    @JsonProperty("AutocheckProxySettings")
    protected ProxySettings autocheckProxySettings;
}
