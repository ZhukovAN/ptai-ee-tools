package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.*;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.misc.tools.TempFile;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.CallHelper;
import lombok.*;
import lombok.experimental.Accessors;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.AiprojV13.Version.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources.i18n_ast_settings_type_manual_json_settings_message_invalid;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.CallHelper.call;
import static org.apache.commons.lang3.StringUtils.isEmpty;

@Slf4j
@Accessors
public abstract class UnifiedAiProjScanSettings {
    private static final List<NonValidationKeyword> NON_VALIDATION_KEYS = Collections.singletonList(new NonValidationKeyword("javaType"));
    protected final ObjectNode rootNode;

    public UnifiedAiProjScanSettings(@NonNull final JsonNode jsonNode) {
        rootNode = (ObjectNode) jsonNode;
    }

    @SneakyThrows
    public String toJson() {
        return createObjectMapper().writeValueAsString(rootNode);
    }

    public Path serializeToFile() throws GenericException {
        return serializeToFile(TempFile.createFile().toPath());
    }

    public Path serializeToFile(@NonNull final Path file) throws GenericException {
        CallHelper.call(() -> {
            String data = this.toJson();
            Files.write(file, data.getBytes(StandardCharsets.UTF_8));
        }, "Data to file serialization failed");
        return file;
    }

    @AllArgsConstructor
    @Getter
    public static class JavaParametersParseResult {
        protected String prefixes;
        protected String other;
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

    @Getter
    @RequiredArgsConstructor
    public static class ParseResult {
        @Getter
        @Setter
        @Builder
        public static class Message {
            public enum Type { INFO, WARNING, ERROR };
            protected Type type;
            protected String text;
        }
        @Setter
        protected UnifiedAiProjScanSettings settings = null;

        protected final List<Message> messages = new ArrayList<>();

        @Setter
        protected GenericException cause;
    }

    @NonNull
    public static ParseResult parse(@NonNull final String data) {
        final ParseResult result = new ParseResult();
        //noinspection ConstantConditions
        do {
            if (isEmpty(data)) {
                result.getMessages().add(ParseResult.Message.builder()
                        .type(ParseResult.Message.Type.ERROR)
                        .text(i18n_ast_settings_type_manual_json_settings_message_empty())
                        .build());
                break;
            }
            final JsonNode root;
            try {
                log.trace("Try to parse AIPROJ as generic JSON data");
                root = call(
                        () -> createObjectMapper().readTree(data),
                        i18n_ast_settings_type_manual_json_settings_message_invalid());
            } catch (GenericException e) {
                result.setCause(e);
                break;
            }

            log.trace("Check Version attribute");
            JsonNode versionNode = root.path("Version");
            UnifiedAiProjScanSettings settings;
            if (versionNode.isMissingNode())
                settings = (root.path("ScanModules").isMissingNode())
                        ? new AiProjLegacyScanSettings(root)
                        : new AiProjV10ScanSettings(root);
            else if (_1_3.value().equals(versionNode.textValue()))
                settings = new AiProjV13ScanSettings(root);
            else if (_1_2.value().equals(versionNode.textValue()))
                settings = new AiProjV12ScanSettings(root);
            else if (_1_1.value().equals(versionNode.textValue()))
                settings = new AiProjV11ScanSettings(root);
            else if (_1_0.value().equals(versionNode.textValue()))
                settings = new AiProjV10ScanSettings(root);
            else {
                result.getMessages().add(ParseResult.Message.builder()
                        .type(ParseResult.Message.Type.ERROR)
                        .text(i18n_ast_settings_type_manual_json_settings_message_version_unknown())
                        .build());
                break;
            }

            log.trace("Check AIPROJ for schema compliance");
            JsonSchemaFactory factory = JsonSchemaFactory
                    .builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V4))
                    .addMetaSchema(JsonMetaSchema
                            .builder(JsonMetaSchema.getV4().getUri(), JsonMetaSchema.getV4())
                            .addKeywords(NON_VALIDATION_KEYS).build()).build();
            log.trace("Validate JSON for AIPROJ schema compliance");
            JsonSchema jsonSchema = factory.getSchema(settings.getJsonSchema());
            Set<ValidationMessage> errors = jsonSchema.validate(root);
            result.getMessages().addAll(settings.processErrorMessages(errors));
            if (result.getMessages().stream().noneMatch((m) -> m.getType().equals(ParseResult.Message.Type.ERROR)))
                result.getMessages().add(ParseResult.Message.builder()
                        .type(ParseResult.Message.Type.INFO)
                        .text(i18n_ast_settings_type_manual_json_settings_message_success(settings.getProjectName(), settings.getProgrammingLanguage().getValue()))
                        .build());
            result.setSettings(settings);
        } while (false);
        return result;
    }

    @NonNull
    protected abstract String getJsonSchema();

    /**
     * Some JSON schema restrictions might be to hard (like email addresses formats,
     * domain names etc.). This method removes low-severity errors from validation results
     * @param errors List of errors to be processed
     */
    public Set<ParseResult.Message> processErrorMessages(Set<ValidationMessage> errors) {
        Set<ParseResult.Message> result = new HashSet<>();
        for (ValidationMessage error : errors)
            result.add(ParseResult.Message.builder()
                    .type(ParseResult.Message.Type.ERROR)
                    .text(error.getMessage())
                    .build());
        return result;
    }

    @Deprecated
    public static UnifiedAiProjScanSettings loadSettings(@NonNull final String data) throws GenericException {
        ParseResult result = parse(data);
        if (null != result.getCause())
            throw result.getCause();
        List<ParseResult.Message> errors = result.getMessages().stream().filter((m) -> m.getType().equals(ParseResult.Message.Type.ERROR)).collect(Collectors.toList());
        if (!errors.isEmpty())
            throw GenericException.raise(
                    i18n_ast_settings_type_manual_json_settings_message_invalid(),
                    new IllegalArgumentException()
            );
        return result.getSettings();
    }

    protected Boolean B(@NonNull final String path) {
        Boolean res = N(path).asBoolean();
        log.trace("JsonPath {} = {}", path, res);
        return res;
    }

    protected Integer I(@NonNull final String path) {
        JsonNode node = N(path);
        Integer res = node.isMissingNode() ? null : node.asInt();
        log.trace("JsonPath {} = {}", path, res);
        return res;
    }

    @NonNull
    protected JsonNode N(@NonNull final String path) {
        return N(rootNode, path);
    }

    @NonNull
    protected JsonNode N(@NonNull final JsonNode rootNode, @NonNull final String path) {
        JsonNode node = rootNode;
        String[] propertyNames = path.split("\\.");
        for (String propertyName : propertyNames) {
            node = node.path(propertyName);
            if (node.isMissingNode()) break;
        }
        return node;
    }

    protected String S(@NonNull final String path) {
        JsonNode resNode = N(path);
        String res = resNode.isMissingNode() || resNode.isNull() ? null : resNode.asText();
        log.trace("JsonPath {} = {}", path, res);
        return res;
    }

    protected Boolean B(@NonNull final JsonNode json, @NonNull final String path) {
        Boolean res = N(json, path).asBoolean();
        log.trace("JsonPath {} = {}", path, res);
        return res;
    }

    protected Integer I(@NonNull final JsonNode json, @NonNull final String path) {
        Integer res = N(json, path).asInt();
        log.trace("JsonPath {} = {}", path, res);
        return res;
    }

    protected String S(@NonNull final JsonNode json, @NonNull final String path) {
        String res = N(json, path).asText();
        log.trace("JsonPath {} = {}", path, res);
        return res;
    }

    public enum Version { LEGACY, V10, V11, V12, V13 }
    public abstract Version getVersion();

    /**
     * Project name i.e. how it will be shown in PT AI UI
     */
    @NonNull
    public abstract String getProjectName();

    public UnifiedAiProjScanSettings setProjectName(@NonNull final String name) {
        rootNode.put("ProjectName", name);
        return this;
    }

    @NonNull
    @Deprecated
    public abstract ScanBrief.ScanSettings.Language getProgrammingLanguage();

    @NonNull
    public Set<ScanBrief.ScanSettings.Language> getProgrammingLanguages() {
        Set<ScanBrief.ScanSettings.Language> res = new HashSet<>();
        res.add(this.getProgrammingLanguage());
        return res;
    }

    public abstract UnifiedAiProjScanSettings setProgrammingLanguage(@NonNull final ScanBrief.ScanSettings.Language language);

    @RequiredArgsConstructor
    public
    enum ScanModule {
        CONFIGURATION("Configuration"),
        COMPONENTS("Components"),
        BLACKBOX("BlackBox"),
        PATTERNMATCHING("PatternMatching"),
        STATICCODEANALYSIS("StaticCodeAnalysis"),
        @Deprecated
        DATAFLOWANALYSIS("DataFlowAnalysis"),
        @Deprecated
        VULNERABLESOURCECODE("VulnerableSourceCode");

        @Getter
        private final String value;
    }
    public abstract Set<UnifiedAiProjScanSettings.ScanModule> getScanModules();
    public abstract UnifiedAiProjScanSettings setScanModules(@NonNull final Set<UnifiedAiProjScanSettings.ScanModule> modules);

    @Deprecated
    public abstract String getCustomParameters();
    @Deprecated
    public abstract UnifiedAiProjScanSettings setCustomParameters(final String parameters);

    @Getter
    @Setter
    @Builder
    @AllArgsConstructor
    public static class WindowsDotNetSettings {
        public enum ProjectType {
            NONE, SOLUTION, WEBSITE
        }
        @Builder.Default
        protected UnifiedAiProjScanSettings.DotNetSettings.ProjectType projectType = UnifiedAiProjScanSettings.DotNetSettings.ProjectType.NONE;
        protected String solutionFile;
        protected Boolean usePublicAnalysisMethod;
        protected Boolean downloadDependencies;
        protected String customParameters;
    }

    public WindowsDotNetSettings getWindowsDotNetSettings() {
        return null;
    }

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
        protected Boolean usePublicAnalysisMethod;
        protected Boolean downloadDependencies;
        protected String customParameters;
    }
    public abstract DotNetSettings getDotNetSettings();

    @Getter
    @Setter
    @Builder
    @AllArgsConstructor
    public static class GoSettings {
        protected Boolean usePublicAnalysisMethod;
        protected String customParameters;
    }

    public GoSettings getGoSettings() {
        return null;
    }

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
            v1_8, v1_11, v1_17
        }
        protected UnifiedAiProjScanSettings.JavaSettings.JavaVersion javaVersion;
        protected Boolean usePublicAnalysisMethod;
        protected Boolean downloadDependencies;
        protected String customParameters;
    }
    public abstract JavaSettings getJavaSettings();

    @Getter
    @Setter
    @Builder
    @AllArgsConstructor
    public static class JavaScriptSettings {
        protected Boolean usePublicAnalysisMethod;
        protected Boolean downloadDependencies;
        protected String customParameters;
    }

    public JavaScriptSettings getJavaScriptSettings() {
        return null;
    }

    @Getter
    @Setter
    @Builder
    @AllArgsConstructor
    public static class PhpSettings {
        protected Boolean usePublicAnalysisMethod;
        protected Boolean downloadDependencies;
        protected String customParameters;
    }

    public PhpSettings getPhpSettings() {
        return null;
    }

    @Getter
    @Setter
    @Builder
    @AllArgsConstructor
    public static class PmTaintSettings {
        protected Boolean usePublicAnalysisMethod;
        protected String customParameters;
    }

    public PmTaintSettings getPmTaintSettings() {
        return null;
    }

    @Getter
    @Setter
    @Builder
    @AllArgsConstructor
    public static class PythonSettings {
        protected Boolean usePublicAnalysisMethod;
        protected Boolean downloadDependencies;
        protected String customParameters;
    }

    public PythonSettings getPythonSettings() {
        return null;
    }

    @NonNull
    public abstract Boolean isSkipGitIgnoreFiles();
    @NonNull
    @Deprecated
    public abstract Boolean isUsePublicAnalysisMethod();

    @Deprecated
    public abstract UnifiedAiProjScanSettings setUsePublicAnalysisMethod(@NonNull final Boolean value);
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
    @Deprecated
    public abstract Boolean isDownloadDependencies();
    @Deprecated
    public abstract UnifiedAiProjScanSettings setDownloadDependencies(@NonNull final Boolean value);

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
                COOKIE
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
