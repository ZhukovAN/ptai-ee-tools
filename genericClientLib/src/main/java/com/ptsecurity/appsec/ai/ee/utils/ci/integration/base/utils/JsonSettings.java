package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class JsonSettings {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class EmailSettings {
        public String SmtpServerAddress;
        public String UserName;
        public String Password;
        public String EmailRecipients;
        public boolean EnableSsl;
        public String Subject;
        public boolean ConsiderCertificateError;
        public String SenderEmail;
    }
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Authentication {
        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class auth_item {
            @JsonIgnoreProperties(ignoreUnknown = true)
            public static class credentials {
                @JsonIgnoreProperties(ignoreUnknown = true)
                public static class login {
                    public String name;
                    public String value;
                    public String regexp;
                    public boolean is_regexp;
                }
                @JsonIgnoreProperties(ignoreUnknown = true)
                public static class password {
                    public String name;
                    public String value;
                    public String regexp;
                    public boolean is_regexp;
                }
                public String cookie;
                public int type;
                public login login;
                public password password;
            }
            public String domain;
            public credentials credentials;
            public String test_url;
            public String form_url;
            public String form_xpath;
            public String regexp_of_success;
        }
        public auth_item auth_item;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ProxySettings {
        public boolean IsEnabled;
        public String Host;
        public String Port;
        public String Type;
        public String Username;
        public String Password;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ReportParameters {
        public String SaveAsPath;
        public boolean UseElectronicSignature;
        public String CertificatePath;
        public String Password;
        public boolean ShowSignatureTime;
        public String SignatureReason;
        public String Location;
        public boolean DoSignatureVisible;
        public boolean IncludeDiscardedVulnerabilities;
        public boolean IncludeSuppressedVulnerabilities;
        public boolean IncludeSuspectedVulnerabilities;
        public boolean IncludeGlossary;
        public boolean ConverHtmlToPdf;
        public boolean RemoveHtml;
        public boolean CreatePdfPrintVersion;
        public boolean MakeAFReport;
        public boolean IncludeDFD;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AutocheckAuthentication {
        public JsonSettings.Authentication.auth_item auth_item;
    }

    // Main settings
    public String ProjectName;
    public String ProgrammingLanguage;
    public String ScanAppType;
    public int ThreadCount;
    public String Site;
    public boolean IsDownloadDependencies;
    public boolean IsUsePublicAnalysisMethod;
    public boolean IsUseEntryAnalysisPoint;
    public boolean IsGraphEnabled;
    public boolean UseIncrementalScan;
    public int ScanUnitTimeout;
    public int PreprocessingTimeout;
    public boolean RunAutocheckAfterScan;
    public String CustomParameters;
    public String[] SkipFileFormats;
    public String[] SkipFilesFolders;
    public boolean UseIssueTrackerIntegration;

    // Java settings
    public boolean IsUnpackUserPackages;
    public String JavaParameters;
    public int JavaVersion;
    public String UseJavaNormalizeVersionPattern;
    public String JavaNormalizeVersionPattern;

    // C# settings
    public String ProjectType;
    public String SolutionFile;
    public String WebSiteFolder;

    // JavaScript settings
    public String JavaScriptProjectFile;

    // Vulnerabilities to find
    public String[] DisabledPatterns;
    public String[] DisabledTypes;

    // YARA Rules
    public boolean UseDefaultFingerprints;
    public boolean UseCustomYaraRules;

    public boolean SendEmailWithReportsAfterScan;
    public boolean CompressReport;

    // Email Settings
    public EmailSettings EmailSettings;

    // BlackBox Settings
    public String Level;
    public String[][] CustomHeaders;
    public Authentication Authentication;

    public ProxySettings ProxySettings;
    public ReportParameters ReportParameters;

    // Autocheck
    public String AutocheckSite;
    public String[][] AutocheckCustomHeaders;
    public Authentication AutocheckAuthentication;
    public ProxySettings AutocheckProxySettings;
}
