package com.ptsecurity.appsec.ai.ee.scan.settings.v36;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.settings.AbstractAiProjScanSettings;
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
public class AiProjScanSettings extends AbstractAiProjScanSettings {

    @JsonProperty("IsUseEntryAnalysisPoint")
    protected Boolean isUseEntryAnalysisPoint;

    @JsonProperty("ScanUnitTimeout")
    protected long scanUnitTimeout;
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
    @JsonProperty("UseJavaNormalizeVersionPattern")
    protected Boolean useJavaNormalizeVersionPattern;
    @JsonProperty("JavaNormalizeVersionPattern")
    protected String javaNormalizeVersionPattern = "-\\d+(\\.\\d+)*";

    // C# settings
    @JsonProperty("WebSiteFolder")
    protected String webSiteFolder;

    // JavaScript settings
    @JsonProperty("JavaScriptProjectFile")
    protected String javaScriptProjectFile;
    @JsonProperty("JavaScriptProjectFolder")
    protected String javaScriptProjectFolder;

    // PMTaint Parameters
    @JsonProperty("DisableInterpretCores")
    protected Boolean disableInterpretCores;

    // YARA Rules
    @JsonProperty("UseDefaultFingerprints")
    protected Boolean useDefaultFingerprints;

    @Getter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Authentication {
        @Getter
        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class Item {
            @JsonProperty("domain")
            protected String domain;

            @Getter
            @JsonIgnoreProperties(ignoreUnknown = true)
            public static class Credentials {
                @JsonProperty("cookie")
                protected String cookie;

                @AllArgsConstructor
                public enum Type {
                    // 0 = Form, 1 = HTTP, 2 = None, 3 = Cookie
                    FORM(0),
                    HTTP(1),
                    NONE(2),
                    COOKIE(3);

                    @JsonValue
                    private final int type;
                }
                @JsonProperty("type")
                protected Type type;

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
                @JsonProperty("login")
                protected Login login;

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
                @JsonProperty("password")
                protected Password password;
            }
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
        @JsonProperty("auth_item")
        protected Item item;
    }
    @JsonProperty("Authentication")
    protected Authentication authentication;

    // Autocheck
    @JsonProperty("AutocheckSite")
    protected String autocheckSite;
    @JsonProperty("AutocheckAuthentication")
    protected Authentication autocheckAuthentication;
    @JsonProperty("AutocheckProxySettings")
    protected ProxySettings autocheckProxySettings;

    @JsonProperty("SendEmailWithReportsAfterScan")
    protected Boolean sendEmailWithReportsAfterScan;
    @JsonProperty("CompressReport")
    protected Boolean compressReport;

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
    @JsonProperty("EmailSettings")
    protected EmailSettings emailSettings;

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
    @JsonProperty("ReportParameters")
    protected ReportParameters reportParameters;

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
        isUseEntryAnalysisPoint = null == isUseEntryAnalysisPoint || isUseEntryAnalysisPoint;
        useIncrementalScan = null == useIncrementalScan || useIncrementalScan;
        super.fix();
        return this;
    }
}