package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.jayway.jsonpath.*;
import com.networknt.schema.*;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.misc.tools.TempFile;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.BaseJsonHelper;
import com.ptsecurity.misc.tools.helpers.CallHelper;
import lombok.*;
import lombok.experimental.Accessors;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;

import static com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.Version._1_0;
import static com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.v11.Version._1_1;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.CallHelper.call;
import static java.lang.Boolean.TRUE;
import static org.apache.commons.lang3.StringUtils.isNotEmpty;

@Slf4j
@Accessors
public abstract class UnifiedAiProjScanSettings implements Cloneable {
    protected final Configuration configuration = Configuration.builder().options(Option.SUPPRESS_EXCEPTIONS).build();
    protected ParseContext ctx;

    protected DocumentContext aiprojDocument;

    public String toJson() {
        return configuration.jsonProvider().toJson(aiprojDocument.read("$"));
    }

    @Override
    public UnifiedAiProjScanSettings clone() {
        try {
            UnifiedAiProjScanSettings clone = (UnifiedAiProjScanSettings) super.clone();
            return clone;
        } catch (CloneNotSupportedException e) {
            throw new AssertionError();
        }
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

    protected static void processJsonNode(final String name, @NonNull final JsonNode node, @NonNull Function<String, String> converter) {
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            fields.forEachRemaining(field -> {
                if (field.getValue().isTextual()) {
                    log.trace("Process {} field", name);
                    ObjectNode objectNode = (ObjectNode) node;
                    objectNode.put(field.getKey(), converter.apply(field.getValue().asText()));
                } else if (field.getValue().isObject())
                    processJsonNode(field.getKey(), field.getValue(), converter);
            });
        } else if (node.isArray()) {
            log.trace("Process JSON array nameless nodes");
            ArrayNode arrayField = (ArrayNode) node;
            arrayField.forEach(item -> processJsonNode(null, item, converter));
        }
    }

    public static String replaceMacro(@NonNull String json, @NonNull Function<String, String> converter) throws GenericException {
        final ObjectMapper mapper = createObjectMapper();
        JsonNode root = call(() -> mapper.readTree(json), "JSON read failed");
        log.trace("Process JSON nameless root node");
        processJsonNode(null, root, converter);
        return call(
                () -> mapper.writeValueAsString(root),
                "JSON serialization failed");
    }

    public UnifiedAiProjScanSettings verifyRequiredFields() throws GenericException {
        call(() -> {
            if (StringUtils.isEmpty(getProjectName()))
                throw new IllegalArgumentException("ProjectName field is not defined or empty");
            if (null == getProgrammingLanguage())
                throw new IllegalArgumentException("ProgrammingLanguage field is not defined or empty");
        }, "JSON settings parse failed");
        return this;
    }

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
        final List<NonValidationKeyword> NON_VALIDATION_KEYS = Collections.singletonList(new NonValidationKeyword("javaType"));
        return call(() -> {
            JsonSchemaFactory factory = JsonSchemaFactory
                    .builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V4))
                    .addMetaSchema(JsonMetaSchema
                            .builder(JsonMetaSchema.getV4().getUri(), JsonMetaSchema.getV4())
                            .addKeywords(NON_VALIDATION_KEYS).build()).build();
            JsonSchema jsonSchema = factory.getSchema(getJsonSchema());
            log.trace("Use JacksonXML parser to process input JSON and remove comments from there");
            JsonNode jsonNode = createObjectMapper().readTree(data);
            log.trace("Validate JSON for AIPROJ schema compliance");
            Set<ValidationMessage> errors = jsonSchema.validate(jsonNode);
            processErrorMessages(errors);
            if (CollectionUtils.isNotEmpty(errors)) {
                log.debug("AIPROJ parse errors:");
                for (ValidationMessage error : errors)
                    log.debug(error.getMessage());
                throw GenericException.raise("AIPROJ schema validation failed", new JsonSchemaException(errors.toString()));
            }
            ctx = JsonPath.using(configuration);
            aiprojDocument = ctx.parse(BaseJsonHelper.minimize(jsonNode));
            return this;
        }, "AIPROJ parse failed");
    }


    @NonNull
    protected abstract String getJsonSchema();

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
        Boolean res = TRUE.equals(O(path));
        log.trace("JsonPath {} = {}", path, res);
        return res;
    }

    protected Integer I(@NonNull final String path) {
        Integer res = O(path);
        log.trace("JsonPath {} = {}", path, res);
        return res;
    }

    protected <T> T O(@NonNull final String path) {
        return aiprojDocument.read(path);
    }

    protected <T> T O(@NonNull final Object json, @NonNull final String path) {
        return ctx.parse(json).read(path);
    }

    protected String S(@NonNull final String path) {
        String res = O(path);
        log.trace("JsonPath {} = {}", path, res);
        return res;
    }

    protected Boolean B(@NonNull final Object json, @NonNull final String path) {
        Boolean res = TRUE.equals(O(json, path));
        log.trace("JsonPath {} = {}", path, res);
        return res;
    }

    protected Integer I(@NonNull final Object json, @NonNull final String path) {
        Integer res = O(json, path);
        log.trace("JsonPath {} = {}", path, res);
        return res;
    }

    protected String S(@NonNull final Object json, @NonNull final String path) {
        String res = O(json, path);
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

    public UnifiedAiProjScanSettings setProjectName(@NonNull final String name) {
        aiprojDocument.put("$", "ProjectName", name);
        return this;
    }

    @NonNull
    public abstract ScanBrief.ScanSettings.Language getProgrammingLanguage();
    public abstract UnifiedAiProjScanSettings setProgrammingLanguage(@NonNull final ScanBrief.ScanSettings.Language language);

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
    public abstract UnifiedAiProjScanSettings setScanModules(@NonNull final Set<UnifiedAiProjScanSettings.ScanModule> modules);

    public abstract String getCustomParameters();
    public abstract UnifiedAiProjScanSettings setCustomParameters(final String parameters);

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
    public abstract Boolean isDownloadDependencies();
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
