package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.fasterxml.jackson.databind.JsonNode;
import com.jayway.jsonpath.*;
import com.networknt.schema.*;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.BaseJsonHelper;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;

import static com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.Version._1_0;
import static com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.Version._1_1;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.CallHelper.call;
import static java.lang.Boolean.TRUE;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

@Slf4j
public abstract class UnifiedAiProjScanSettings {
    protected final ParseContext ctx = JsonPath.using(Configuration.builder().options(Option.SUPPRESS_EXCEPTIONS).build());
    protected Object aiprojDocument;

    @AllArgsConstructor
    @Getter
    public static class JavaParametersParseResult {
        protected String prefixes;
        protected String other;
    }

    /**
     * @param javaParameters Java CLI parameters that are passed to Java scanning core
     * @return CLI parameters split into two parts: {@link JavaParametersParseResult#prefixes user package prefixes}
     * and {@link JavaParametersParseResult#other remaining part of CLI}
     */
    public static JavaParametersParseResult parseJavaParameters(final String javaParameters) {
        if (StringUtils.isEmpty(javaParameters)) return null;
        log.trace("Split Java parameters string using 'quote-safe' regular expression");
        String[] parameters = javaParameters.split("(\"[^\"]*\")|(\\S+)");
        if (0 == parameters.length) return null;
        log.trace("Parse Java parameters");
        List<String> commands = new ArrayList<>();
        Map<String, List<String>> arguments = new HashMap<>();
        for (int i = 0 ; i < parameters.length ; i++) {
            log.trace("Iterate through commands");
            if (!parameters[i].startsWith("-")) continue;
            if (parameters.length - 1 == i)
                // If this is last token just add it as command
                commands.add(parameters[i]);
            else if (parameters[i + 1].startsWith("-"))
                // Next token is a command too
                commands.add(parameters[i]);
            else {
                List<String> argumentValues = new ArrayList<>();
                for (int j = i + 1; j < parameters.length; j++)
                    if (!parameters[j].startsWith("-")) argumentValues.add(parameters[j]); else break;
                arguments.put(parameters[i], argumentValues);
            }
        }
        String prefixes = "";
        StringBuilder commandBuilder = new StringBuilder();
        for (String cmd : commands) {
            if ("-upp".equals(cmd) || "--user-package=prefix".equals(cmd))
                if (arguments.containsKey(cmd) && 1 == arguments.get(cmd).size())
                    prefixes = arguments.get(cmd).get(0);
                else {
                    commandBuilder.append(cmd).append(" ");
                    if (arguments.containsKey(cmd))
                        commandBuilder.append(String.join(" ", arguments.get(cmd))).append(" ");
                }
        }
        return new JavaParametersParseResult(prefixes, commandBuilder.toString().trim());
    }

    /**
     * In PT AI v.4.1 solution file is to be defined as "./solution.sln" instead of "solution.sln"
     * @param solutionFile Initial solution file name
     * @return Fixed solution file name
     */
    public static String fixSolutionFile(final String solutionFile) {
        String res = solutionFile;
        // noinspection ConstantConditions
        do {
            if (StringUtils.isEmpty(solutionFile)) break;
            res = solutionFile.trim();
            if (solutionFile.startsWith("./")) break;
            log.trace("Fix solution file name {}", solutionFile);
            res = "./" + solutionFile;
            log.trace("Fixed solution file name is {}", solutionFile);
        } while (false);
        return res;
    }

    public UnifiedAiProjScanSettings parse(@NonNull final String data) throws GenericException {
        return call(() -> {
            JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V4);
            JsonSchema jsonSchema = factory.getSchema(getJsonSchema());
            log.trace("Use JacksonXML parser to process input JSON and remove comments from there");
            JsonNode jsonNode = createObjectMapper().readTree(data);
            Set<ValidationMessage> errors = jsonSchema.validate(jsonNode);
            processErrorMessages(errors);
            if (CollectionUtils.isNotEmpty(errors)) {
                log.debug("AIPROJ parse errors:");
                for (ValidationMessage error : errors)
                    log.debug(error.getMessage());
                throw GenericException.raise("AIPROJ schema validation failed", new JsonSchemaException(errors.toString()));
            }
            // aiprojDocument = BaseJsonHelper.minimize(jsonNode); // Configuration.defaultConfiguration().jsonProvider().parse(data);
            aiprojDocument = Configuration.defaultConfiguration().jsonProvider().parse(BaseJsonHelper.minimize(jsonNode));
            return this;
        }, "AIPROJ parse failed");
    }


    @NonNull
    public abstract String getJsonSchema();

    /**
     * Some JSON schema restrictions might be to hard (like email addresses formats,
     * domain names etc.). This method removes low-severity errors from validation results
     * @param errors List of errors to be processed
     */
    public void processErrorMessages(Set<ValidationMessage> errors) {};

    public static UnifiedAiProjScanSettings loadSettings(@NonNull final String data) throws GenericException {
        ParseContext ctx = JsonPath.using(Configuration.builder().options(Option.SUPPRESS_EXCEPTIONS).build());
        DocumentContext doc = ctx.parse(BaseJsonHelper.minimize(data));
        String version = doc.read("$.Version");
        if (isNotEmpty(version)) {
            log.trace("Detected AIPROJ version {}", version);
            if (_1_1.value().equals(version))
                return new AiProjV11ScanSettings().parse(data);
            else if (_1_0.value().equals(version)) {
                return new AiProjV10ScanSettings().parse(data);
            } else
                throw GenericException.raise("AIPROJ parse failed", new IllegalArgumentException("Unsupported AIPROJ version " + version));
        } else if (null != doc.read("$.ScanModules")) {
            log.trace("Parse AIPROJ as v.1.0 as there's no version, but ScanModules are defined");
            return new AiProjV10ScanSettings().parse(data);
        } else {
            log.trace("Parse legacy AIPROJ as there's no version and no ScanModules are defined");
            return new AiProjLegacyScanSettings().parse(data);
        }
    }

    protected Boolean B(@NonNull final String path) {
        return B(aiprojDocument, path);
    }

    protected Integer I(@NonNull final String path) {
        return I(aiprojDocument, path);
    }

    protected Object O(@NonNull final String path) {
        return O(aiprojDocument, path);
    }

    protected <T> T O(@NonNull final Object json, @NonNull final String path) {
        return ctx.parse(json).read(path);
    }

    protected String S(@NonNull final String path) {
        return S(aiprojDocument, path);
    }

    protected Boolean B(@NonNull final Object json, @NonNull final String path) {
        Boolean res = TRUE.equals(ctx.parse(json).read(path));
        log.trace("JsonPath {} = {}", path, res);
        return res;
    }

    protected Integer I(@NonNull final Object json, @NonNull final String path) {
        return ctx.parse(json).read(path);
    }

    protected String S(@NonNull final Object json, @NonNull final String path) {
        String res = ctx.parse(json).read(path);
        log.trace("JsonPath {} = {}", path, res);
        return res;
    }

    enum Version { LEGACY, V10, V11 }
    public abstract Version getVersion();

    /**
     * Project name i.e. how it will be shown in PT AI viewer interface
     */
    @NonNull
    public abstract String getProjectName();

    @NonNull
    public abstract ScanBrief.ScanSettings.Language getProgrammingLanguage();

    @RequiredArgsConstructor
    public
    enum ScanModule {
        CONFIGURATION("Configuration"),
        COMPONENTS("Components"),
        BLACKBOX("BlackBox"),
        DATAFLOWANALYSIS("DataFlowAnalysis"),
        PATTERNMATCHING("PatternMatching"),
        VULNERABLESOURCECODE("VulnerableSourceCode");

        @Getter
        private final String value;
    }
    public abstract Set<UnifiedAiProjScanSettings.ScanModule> getScanModules();

    public abstract String getCustomParameters();

    @Getter
    @Setter
    @Builder
    @AllArgsConstructor
    public static class DotNetSettings {
        public enum ProjectType {
            NONE, SOLUTION, WEBSITE
        }
        @Builder.Default
        protected UnifiedAiProjScanSettings.DotNetSettings.ProjectType projectType = UnifiedAiProjScanSettings.DotNetSettings.ProjectType.NONE;
        protected String solutionFile;
        @Deprecated
        protected String webSiteFolder;
    }
    public abstract DotNetSettings getDotNetSettings();

    @Getter
    @Setter
    @Builder
    @AllArgsConstructor
    public static class JavaSettings {
        protected String parameters;
        @Builder.Default
        protected Boolean unpackUserPackages = false;
        protected String userPackagePrefixes;
        public enum JavaVersion {
            v1_8, v1_11
        }
        protected UnifiedAiProjScanSettings.JavaSettings.JavaVersion javaVersion;
    }
    public abstract JavaSettings getJavaSettings();

    @NonNull
    public abstract Boolean isSkipGitIgnoreFiles();
    @NonNull
    public abstract Boolean isUsePublicAnalysisMethod();
    @NonNull
    public abstract Boolean isUseSastRules();
    @NonNull
    public abstract Boolean isUseCustomPmRules();

    @NonNull
    @Deprecated
    public abstract Boolean isUseCustomYaraRules();

    @NonNull
    public abstract Boolean isUseSecurityPolicies();
    @NonNull
    public abstract Boolean isDownloadDependencies();

    @Getter
    @Setter
    @Builder
    @AllArgsConstructor
    public static class MailingProjectSettings {
        @NonNull
        @Builder.Default
        protected Boolean enabled = false;
        protected String mailProfileName;
        @Builder.Default
        protected List<String> emailRecipients = new ArrayList<>();
    }
    public abstract MailingProjectSettings getMailingProjectSettings();

    @Getter
    @Setter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class BlackBoxSettings {
        protected List<Pair<String, String>> httpHeaders;
        @Deprecated
        protected List<Pair<String, String>> autocheckHttpHeaders;

        @Getter
        @Setter
        @Builder
        @AllArgsConstructor
        public static class AddressListItem {
            public enum Format {
                WILDCARD, EXACTMATCH, REGEXP
            }
            protected UnifiedAiProjScanSettings.BlackBoxSettings.AddressListItem.Format format;
            protected String address;
        }
        protected List<UnifiedAiProjScanSettings.BlackBoxSettings.AddressListItem> whiteListedAddresses;
        protected List<UnifiedAiProjScanSettings.BlackBoxSettings.AddressListItem> blackListedAddresses;

        public enum ScanLevel {
            NONE,
            FAST,
            FULL,
            NORMAL
        }
        protected UnifiedAiProjScanSettings.BlackBoxSettings.ScanLevel scanLevel;

        public enum ScanScope {
            FOLDER,
            DOMAIN,
            PATH
        }
        protected UnifiedAiProjScanSettings.BlackBoxSettings.ScanScope scanScope;

        protected String site;

        @Builder.Default
        protected Boolean sslCheck = false;

        @Builder.Default
        protected Boolean runAutocheckAfterScan = false;

        @Deprecated
        protected String autocheckSite;

        @Getter
        @Setter
        @Builder
        @AllArgsConstructor
        public static class ProxySettings {
            Boolean enabled;
            String host;
            String login;
            String password;
            Integer port;

            public enum Type {
                HTTP, HTTPNOCONNECT, SOCKS4, SOCKS5
            }
            UnifiedAiProjScanSettings.BlackBoxSettings.ProxySettings.Type type;
        }
        protected UnifiedAiProjScanSettings.BlackBoxSettings.ProxySettings proxySettings;
        @Deprecated
        protected UnifiedAiProjScanSettings.BlackBoxSettings.ProxySettings autocheckProxySettings;

        @Getter
        @Setter
        @SuperBuilder
        @NoArgsConstructor
        @AllArgsConstructor
        public static class Authentication {
            public static final UnifiedAiProjScanSettings.BlackBoxSettings.Authentication NONE = new UnifiedAiProjScanSettings.BlackBoxSettings.Authentication();
            public enum Type {
                FORM,
                HTTP,
                NONE,
                COOKIE;
            }
            @NonNull
            @Builder.Default
            protected UnifiedAiProjScanSettings.BlackBoxSettings.Authentication.Type type = UnifiedAiProjScanSettings.BlackBoxSettings.Authentication.Type.NONE;
        }
        @Getter
        @Setter
        @SuperBuilder
        @NoArgsConstructor
        @AllArgsConstructor
        public static class CookieAuthentication extends UnifiedAiProjScanSettings.BlackBoxSettings.Authentication {
            protected String cookie;
            protected String validationAddress;
            protected String validationTemplate;
        }
        @Getter
        @Setter
        @SuperBuilder
        @NoArgsConstructor
        @AllArgsConstructor
        public static class HttpAuthentication extends UnifiedAiProjScanSettings.BlackBoxSettings.Authentication {
            protected String login;
            protected String password;
            protected String validationAddress;
        }
        @Getter
        @Setter
        @SuperBuilder
        @NoArgsConstructor
        @AllArgsConstructor
        public static class FormAuthentication extends UnifiedAiProjScanSettings.BlackBoxSettings.Authentication {
            public enum DetectionType { AUTO, MANUAL }
            protected UnifiedAiProjScanSettings.BlackBoxSettings.FormAuthentication.DetectionType detectionType;
            protected String formAddress;
            protected String loginKey;
            protected String login;
            protected String passwordKey;
            protected String password;
            protected String validationTemplate;
            protected String xPath;
        }
        protected BlackBoxSettings.Authentication authentication;
        @Deprecated
        protected BlackBoxSettings.Authentication autocheckAuthentication;
    }
    public abstract BlackBoxSettings getBlackBoxSettings();
}
