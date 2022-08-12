package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v41.converters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.scan.settings.v41.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.server.v41.projectmanagement.model.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonPolicyHelper;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper.createObjectMapper;

@Slf4j
public class AiProjConverter {
    private static final Map<AiProjScanSettings.BlackBoxScanLevel, BlackBoxScanLevel> BLACKBOX_SCAN_LEVEL_MAP = new HashMap<>();
    private static final Map<AiProjScanSettings.BlackBoxScanScope, ScanScope> BLACKBOX_SCAN_SCOPE_MAP = new HashMap<>();
    private static final Map<AiProjScanSettings.Authentication.Item.Credentials.Type, AuthType> BLACKBOX_AUTH_TYPE_MAP = new HashMap<>();
    private static final Map<AiProjScanSettings.ProxySettings.Type, ProxyType> BLACKBOX_PROXY_TYPE_MAP = new HashMap<>();
    private static final Map<ScanResult.ScanSettings.Language, ProgrammingLanguageGroup> REVERSE_LANGUAGE_GROUP_MAP = new HashMap<>();

    static {
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.NONE, BlackBoxScanLevel.NONE);
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.FAST, BlackBoxScanLevel.FAST);
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.NORMAL, BlackBoxScanLevel.NORMAL);
        BLACKBOX_SCAN_LEVEL_MAP.put(AiProjScanSettings.BlackBoxScanLevel.FULL, BlackBoxScanLevel.FULL);

        BLACKBOX_SCAN_SCOPE_MAP.put(AiProjScanSettings.BlackBoxScanScope.DOMAIN, ScanScope.DOMAIN);
        BLACKBOX_SCAN_SCOPE_MAP.put(AiProjScanSettings.BlackBoxScanScope.FOLDER, ScanScope.FOLDER);
        BLACKBOX_SCAN_SCOPE_MAP.put(AiProjScanSettings.BlackBoxScanScope.PATH, ScanScope.PATH);

        BLACKBOX_AUTH_TYPE_MAP.put(AiProjScanSettings.Authentication.Item.Credentials.Type.FORM, AuthType.FORM);
        BLACKBOX_AUTH_TYPE_MAP.put(AiProjScanSettings.Authentication.Item.Credentials.Type.HTTP, AuthType.HTTP);
        BLACKBOX_AUTH_TYPE_MAP.put(AiProjScanSettings.Authentication.Item.Credentials.Type.NONE, AuthType.NONE);
        BLACKBOX_AUTH_TYPE_MAP.put(AiProjScanSettings.Authentication.Item.Credentials.Type.COOKIE, AuthType.RAWCOOKIE);

        BLACKBOX_PROXY_TYPE_MAP.put(AiProjScanSettings.ProxySettings.Type.HTTP, ProxyType.HTTP);
        BLACKBOX_PROXY_TYPE_MAP.put(AiProjScanSettings.ProxySettings.Type.HTTPNOCONNECT, ProxyType.HTTPNOCONNECT);
        BLACKBOX_PROXY_TYPE_MAP.put(AiProjScanSettings.ProxySettings.Type.SOCKS4, ProxyType.SOCKS4);
        BLACKBOX_PROXY_TYPE_MAP.put(AiProjScanSettings.ProxySettings.Type.SOCKS5, ProxyType.SOCKS5);

        REVERSE_LANGUAGE_GROUP_MAP.put(ScanBrief.ScanSettings.Language.CPP, ProgrammingLanguageGroup.CANDCPLUSPLUS);
        REVERSE_LANGUAGE_GROUP_MAP.put(ScanBrief.ScanSettings.Language.GO, ProgrammingLanguageGroup.GO);
        REVERSE_LANGUAGE_GROUP_MAP.put(ScanBrief.ScanSettings.Language.JAVASCRIPT, ProgrammingLanguageGroup.JAVASCRIPT);
        REVERSE_LANGUAGE_GROUP_MAP.put(ScanBrief.ScanSettings.Language.CSHARP, ProgrammingLanguageGroup.CSHARP);
        REVERSE_LANGUAGE_GROUP_MAP.put(ScanBrief.ScanSettings.Language.JAVA, ProgrammingLanguageGroup.JAVA);
        REVERSE_LANGUAGE_GROUP_MAP.put(ScanBrief.ScanSettings.Language.KOTLIN, ProgrammingLanguageGroup.KOTLIN);
        REVERSE_LANGUAGE_GROUP_MAP.put(ScanBrief.ScanSettings.Language.SQL, ProgrammingLanguageGroup.SQL);
        REVERSE_LANGUAGE_GROUP_MAP.put(ScanBrief.ScanSettings.Language.PYTHON, ProgrammingLanguageGroup.PYTHON);
        REVERSE_LANGUAGE_GROUP_MAP.put(ScanBrief.ScanSettings.Language.SWIFT, ProgrammingLanguageGroup.SWIFT);
        REVERSE_LANGUAGE_GROUP_MAP.put(ScanBrief.ScanSettings.Language.VB, ProgrammingLanguageGroup.VB);
        REVERSE_LANGUAGE_GROUP_MAP.put(ScanBrief.ScanSettings.Language.PHP, ProgrammingLanguageGroup.PHP);
        REVERSE_LANGUAGE_GROUP_MAP.put(ScanBrief.ScanSettings.Language.OBJECTIVEC, ProgrammingLanguageGroup.OBJECTIVEC);
    }

    protected static WhiteBoxSettingsModel apply(@NonNull final AiProjScanSettings settings, @NonNull WhiteBoxSettingsModel model) {
        log.trace("Parse AIPROJ vulnerability search modules list");
        // Vulnerability search modules. Possible values are: Php, Java, CSharp, Configuration,
        // Fingerprint (includes DependencyCheck), PmTaint , BlackBox, JavaScript
        Set<AiProjScanSettings.ScanAppType> scanAppTypes = Arrays.stream(settings.getScanAppType().split("[, ]+"))
                .map(AiProjScanSettings.ScanAppType::from)
                .collect(Collectors.toSet());

        log.trace("Set base project whitebox settings");
        // Check if PHP / Java / C# / JavaScript modules are to be engaged
        final Set<AiProjScanSettings.ScanAppType> abstractInterpretationEngines = new HashSet<>(Arrays.asList(AiProjScanSettings.ScanAppType.PHP, AiProjScanSettings.ScanAppType.JAVA, AiProjScanSettings.ScanAppType.CSHARP, AiProjScanSettings.ScanAppType.JAVASCRIPT));
        model.setSearchForVulnerableSourceCodeEnabled(scanAppTypes.stream().anyMatch(abstractInterpretationEngines::contains));
        model.setDataFlowAnalysisEnabled(null != settings.getUseTaintAnalysis() && settings.getUseTaintAnalysis() && scanAppTypes.contains(AiProjScanSettings.ScanAppType.PMTAINT));
        model.setPatternMatchingEnabled(null != settings.getUsePmAnalysis() && settings.getUsePmAnalysis() && scanAppTypes.contains(AiProjScanSettings.ScanAppType.PMTAINT));
        model.setSearchForConfigurationFlawsEnabled(scanAppTypes.contains(AiProjScanSettings.ScanAppType.CONFIGURATION));
        model.setSearchForVulnerableComponentsEnabled(scanAppTypes.contains(AiProjScanSettings.ScanAppType.FINGERPRINT));

        return model;
    }

    @NonNull
    protected static BlackBoxSettingsModel apply(@NonNull final AiProjScanSettings settings, @NonNull final BlackBoxSettingsModel model) {
        model.setAuthentication(AuthType.NONE);

        log.trace("Check if AIPROJ authentication field is defined");
        if (null == settings.getAuthentication()) return model;
        AiProjScanSettings.Authentication.Item jsonAuth = settings.getAuthentication().getItem();
        if (null == jsonAuth) return model;

        model.setDomainName(jsonAuth.getDomain());
        model.setFormUrl(jsonAuth.getFormUrl());
        model.setFormXpath(jsonAuth.getFormXPath());
        model.setTestUrl(jsonAuth.getTestUrl());
        model.setValidationRegexTemplate(jsonAuth.getRegexpOfSuccess());


        if (null == jsonAuth.getCredentials()) return model;

        model.setAuthentication(BLACKBOX_AUTH_TYPE_MAP.getOrDefault(jsonAuth.getCredentials().getType(), AuthType.NONE));
        if (AuthType.RAWCOOKIE.equals(model.getAuthentication())) {
            log.trace("Set cookie authentication");
            if (null != jsonAuth.getCredentials())
                model.setCookie(jsonAuth.getCredentials().getCookie());
        } else if (AuthType.FORM.equals(model.getAuthentication())) {
            log.trace("Set form authentication");
            if (null != jsonAuth.getCredentials()) {
                if (null != jsonAuth.getCredentials().getLogin()) {
                    model.setLoginKey(jsonAuth.getCredentials().getLogin().getName());
                    model.setLogin(jsonAuth.getCredentials().getLogin().getValue());
                }
                if (null != jsonAuth.getCredentials().getPassword()) {
                    model.setPasswordKey(jsonAuth.getCredentials().getPassword().getName());
                    model.setPassword(jsonAuth.getCredentials().getPassword().getValue());
                }
            }
        } else if (AuthType.HTTP.equals(model.getAuthentication())) {
            log.trace("Set HTTP authentication");
            if (null != jsonAuth.getCredentials()) {
                if (null != jsonAuth.getCredentials().getLogin())
                    model.setLogin(jsonAuth.getCredentials().getLogin().getValue());
                if (null != jsonAuth.getCredentials().getPassword())
                    model.setPassword(jsonAuth.getCredentials().getPassword().getValue());
            }
        }

        model.setRunAutocheckAfterScan(settings.getRunAutocheckAfterScan());
        return model;
    }

    @SneakyThrows
    public static BaseProjectSettingsModel convert(
            @NonNull final AiProjScanSettings settings,
            @NonNull final BaseProjectSettingsModel defaultSettings) {
        // Create deep settings copy
        ObjectMapper objectMapper = new ObjectMapper();
        BaseProjectSettingsModel result = objectMapper.readValue(objectMapper.writeValueAsString(defaultSettings), BaseProjectSettingsModel.class);

        log.trace("Set base project settings");
        result.setName(settings.getProjectName());
        result.setProgrammingLanguageGroup(convertLanguageGroup(settings.getProgrammingLanguage()));
        result.setProjectUrl(settings.getSite());

        result.setWhiteBox(apply(settings, new WhiteBoxSettingsModel()));

        // Vulnerability search modules. Possible values are: Php, Java, CSharp, Configuration,
        // Fingerprint (includes DependencyCheck), PmTaint , BlackBox, JavaScript
        Set<AiProjScanSettings.ScanAppType> scanAppTypes = Arrays.stream(settings.getScanAppType().split("[, ]+"))
                .map(AiProjScanSettings.ScanAppType::from)
                .collect(Collectors.toSet());
        result.setBlackBoxEnabled(scanAppTypes.contains(AiProjScanSettings.ScanAppType.BLACKBOX));
        if (Boolean.TRUE.equals(result.getBlackBoxEnabled())) {
            log.trace("Set base project blackbox settings");
            result.setBlackBox(apply(settings, new BlackBoxSettingsModel()));
        }

        return result;
    }

    /**
     * Method converts PT AI API version independent language to PT AI v.4.0 API programming language group
     * @param language PT AI API version independent language
     * @return PT AI v.4.0 API programming language group
     */
    @NonNull
    public static ProgrammingLanguageGroup convertLanguageGroup(@NonNull final ScanResult.ScanSettings.Language language) {
        return REVERSE_LANGUAGE_GROUP_MAP.getOrDefault(language, ProgrammingLanguageGroup.NONE);
    }

    @AllArgsConstructor
    @Getter
    protected static class JavaParametersParseResult {
        protected String prefixes;
        protected String other;
    }

    /**
     * @param javaParameters Java CLI parameters that are passed to Java scanning core
     * @return CLI parameters split into two parts: {@link JavaParametersParseResult#prefixes user package prefixes}
     * and {@link JavaParametersParseResult#other remaining part of CLI}
     */
    protected static JavaParametersParseResult parseJavaParameters(final String javaParameters) {
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

    @SneakyThrows
    public static AdditionalParams apply(
            @NonNull final AiProjScanSettings settings,
            @NonNull final AdditionalParams model) {
        // Set isUnpackUserJarFiles
        model.setIsUnpackUserJarFiles(settings.getIsUnpackUserPackages());
        // Set userPackagePrefixes and launchJvmParameters
        log.trace("Try to extract user package prefixes from Java parameters");
        // noinspection ConstantConditions
        do {
            if (StringUtils.isEmpty(settings.getJavaParameters())) break;
            JavaParametersParseResult parseResult = parseJavaParameters(settings.getJavaParameters());
            if (null == parseResult) break;
            model.setUserPackagePrefixes(parseResult.getPrefixes());
            model.setLaunchJvmParameters(parseResult.getOther());
        } while (false);
        // Set jdkVersion
        model.setJdkVersion(0 == settings.getJavaVersion() ? JavaVersions.v1_8 : JavaVersions.v1_11);
        // Set projectType
        model.setProjectType(
                DotNetProjectType.SOLUTION.getValue().equalsIgnoreCase(settings.getProjectType())
                        ? DotNetProjectType.SOLUTION
                        : DotNetProjectType.WEBSITE.getValue().equalsIgnoreCase(settings.getProjectType())
                        ? DotNetProjectType.WEBSITE : DotNetProjectType.NONE);
        // In PT AI v.4.1 solution file is to be defined as "./solution.sln" instead of "solution.sln"
        String solutionFile = settings.getSolutionFile();
        do {
            if (StringUtils.isEmpty(solutionFile)) break;
            solutionFile = solutionFile.trim();
            if (solutionFile.startsWith("./")) break;
            log.trace("Fix solution file name {}", solutionFile);
            solutionFile = "./" + solutionFile;
            log.trace("Fixed solution file name is {}", solutionFile);
        } while (false);
        model.setSolutionFile(solutionFile);
        return model;
    }

    /**
     * Method sets project settings attributes using AIPROJ-defined ones
     * @param settings
     * @param model
     * @return
     */
    @SneakyThrows
    public static ProjectSettingsModel apply(
            @NonNull final AiProjScanSettings settings,
            @NonNull final ProjectSettingsModel model) {
        log.trace("Set base project settings");
        // Set projectSource
        model.setProjectSource(new ProjectSourceModel().sourceType(SourceType.EMPTY));
        // Set projectName
        model.setProjectName(settings.getProjectName());
        // Set programmingLanguageGroup
        model.setProgrammingLanguageGroup(convertLanguageGroup(settings.getProgrammingLanguage()));
        // Set whiteBoxSettings
        model.setWhiteBoxSettings(apply(settings, new WhiteBoxSettingsModel()));
        // Set launchParameters
        model.setLaunchParameters(settings.getCustomParameters());
        //Set useAvailablePublicAndProtectedMethods
        model.setUseAvailablePublicAndProtectedMethods(settings.getIsUsePublicAnalysisMethod());
        // Set isLoadDependencies
        model.setIsLoadDependencies(settings.getIsDownloadDependencies());
        // Set additionalParams
        AdditionalParams additionalParams = model.getAdditionalParams();
        if (null == additionalParams) {
            additionalParams = new AdditionalParams();
            model.setAdditionalParams(additionalParams);
        }
        apply(settings, additionalParams);
        return model;
    }

    @SneakyThrows
    public static PatchBlackBoxAuthenticationModel apply(
            @NonNull final AiProjScanSettings source,
            @NonNull final PatchBlackBoxAuthenticationModel destination) {
        destination.setType(AuthType.NONE);
        log.trace("Check if AIPROJ authentication field is defined");
        if (null == source.getAuthentication()) return destination;
        AiProjScanSettings.Authentication.Item jsonAuth = source.getAuthentication().getItem();
        if (null == jsonAuth) return destination;

        destination.setValidationAddress(jsonAuth.getTestUrl());
        destination.setFormUrl(jsonAuth.getFormUrl());
        destination.setFormXpath(jsonAuth.getFormXPath());
        destination.setValidationTemplate(jsonAuth.getRegexpOfSuccess());
        // TODO: Check {@link AuthItem.getDomain} parameter
        if (null == jsonAuth.getCredentials()) return destination;
        destination.setType(BLACKBOX_AUTH_TYPE_MAP.getOrDefault(jsonAuth.getCredentials().getType(), AuthType.NONE));
        if (AuthType.RAWCOOKIE.equals(destination.getType())) {
            log.trace("Set cookie authentication");
            if (null != jsonAuth.getCredentials())
                destination.setCookie(jsonAuth.getCredentials().getCookie());
        } else if (AuthType.FORM.equals(destination.getType())) {
            log.trace("Set form authentication");
            if (null != jsonAuth.getCredentials()) {
                if (null != jsonAuth.getCredentials().getLogin()) {
                    destination.setLoginKey(jsonAuth.getCredentials().getLogin().getName());
                    destination.setLogin(jsonAuth.getCredentials().getLogin().getValue());
                }
                if (null != jsonAuth.getCredentials().getPassword()) {
                    destination.setPasswordKey(jsonAuth.getCredentials().getPassword().getName());
                    destination.setPassword(jsonAuth.getCredentials().getPassword().getValue());
                }
            }
        } else if (AuthType.HTTP.equals(destination.getType())) {
            log.trace("Set HTTP authentication");
            if (null != jsonAuth.getCredentials()) {
                if (null != jsonAuth.getCredentials().getLogin())
                    destination.setLogin(jsonAuth.getCredentials().getLogin().getValue());
                if (null != jsonAuth.getCredentials().getPassword())
                    destination.setPassword(jsonAuth.getCredentials().getPassword().getValue());
            }
        }
        return destination;
    }

    @SneakyThrows
    protected static PatchBlackBoxProxySettingsModel apply(
            @NonNull final AiProjScanSettings.ProxySettings source,
            @NonNull final PatchBlackBoxProxySettingsModel destination) {
        destination.setIsActive(null != source.getType());
        if (Boolean.FALSE.equals(destination.getIsActive())) return destination;
        destination.setType(BLACKBOX_PROXY_TYPE_MAP.get(source.getType()));
        destination.setHost(source.getHost());
        destination.setPort(source.getPort());
        destination.setLogin(source.getUsername());
        destination.setPassword(source.getPassword());
        return destination;
    }

    @SneakyThrows
    protected static PatchBlackBoxProxySettingsModel apply(final AiProjScanSettings.ProxySettings source) {
        return null == source ? null : apply(source, new PatchBlackBoxProxySettingsModel());
    }

    @SneakyThrows
    protected static PatchBlackBoxProxySettingsModel apply(
            @NonNull final BlackBoxProxySettingsModel source,
            @NonNull final PatchBlackBoxProxySettingsModel destination) {
        destination.setIsActive(source.getIsActive());
        destination.setType(source.getType());
        destination.setHost(source.getHost());
        destination.setPort(source.getPort());
        destination.setLogin(source.getLogin());
        destination.setPassword(source.getPassword());
        return destination;
    }

    @SneakyThrows
    protected static PatchBlackBoxProxySettingsModel apply(
            final BlackBoxProxySettingsModel source) {
        return null == source ? null : apply(source, new PatchBlackBoxProxySettingsModel());
    }

    @SneakyThrows
    protected static PatchBlackBoxAuthenticationModel apply(
            @NonNull final BlackBoxAuthenticationModel source,
            @NonNull final PatchBlackBoxAuthenticationModel destination) {
        destination.setType(source.getType());
        destination.setCookie(source.getCookie());
        destination.setFormUrl(source.getFormUrl());
        destination.setFormXpath(source.getFormXpath());
        destination.setLogin(source.getLogin());
        destination.setLoginKey(source.getLoginKey());
        destination.setPassword(source.getPassword());
        destination.setPasswordKey(source.getPasswordKey());
        return destination;
    }

    @SneakyThrows
    protected static PatchBlackBoxAuthenticationModel apply(
            final BlackBoxAuthenticationModel source) {
        return null == source ? null : apply(source, new PatchBlackBoxAuthenticationModel());
    }

    @SneakyThrows
    public static PatchBlackBoxSettingsModel apply(
            @NonNull final ExtendedBlackBoxSettingsModel source,
            @NonNull final PatchBlackBoxSettingsModel destination) {
        destination.setHost(source.getHost());
        destination.setRunAutocheckAfterScan(source.getRunAutocheckAfterScan());
        destination.setAdditionalHttpHeaders(source.getAdditionalHttpHeaders());
        destination.setAuthentication(apply(source.getAuthentication()));
        destination.setIsActive(source.getIsActive());
        destination.setScanLevel(source.getScanLevel());
        destination.setScanScope(source.getScanScope());
        destination.setProxySettings(apply(source.getProxySettings()));
        return destination;
    }

    @SneakyThrows
    public static PatchBlackBoxSettingsModel apply(
            @NonNull final AiProjScanSettings settings,
            @NonNull final PatchBlackBoxSettingsModel model) {
        model.setRunAutocheckAfterScan(settings.getRunAutocheckAfterScan());
        model.setHost(settings.getSite());
        Set<AiProjScanSettings.ScanAppType> scanAppTypes = Arrays.stream(settings.getScanAppType().split("[, ]+"))
                .map(AiProjScanSettings.ScanAppType::from)
                .collect(Collectors.toSet());
        if (!scanAppTypes.contains(AiProjScanSettings.ScanAppType.BLACKBOX)) return model;
        model.setIsActive(true);
        model.setScanLevel(BLACKBOX_SCAN_LEVEL_MAP.get(settings.getBlackBoxScanLevel()));
        model.setScanScope(BLACKBOX_SCAN_SCOPE_MAP.get(settings.getBlackBoxScanScope()));
        if (CollectionUtils.isNotEmpty(settings.getCustomHeaders())) {
            log.trace("Set additional HTTP headers");
            List<AdditionalHttpHeader> headers = new ArrayList<>();
            for (List<String> header : settings.getCustomHeaders()) {
                if (2 != header.size()) continue;
                headers.add(new AdditionalHttpHeader().key(header.get(0)).value(header.get(1)));
            }
            model.setAdditionalHttpHeaders(headers);
        }
        model.setAuthentication(apply(settings, new PatchBlackBoxAuthenticationModel()));
        model.setProxySettings(null == settings.getProxySettings() ? null : apply(settings.getProxySettings()));
        return model;
    }

    @SneakyThrows
    public static SecurityPoliciesModel apply(
            final Policy[] policy,
            @NonNull final SecurityPoliciesModel model) {
        model.setCheckSecurityPoliciesAccordance(null != policy && 0 != policy.length);
        model.setSecurityPolicies(Boolean.TRUE.equals(model.getCheckSecurityPoliciesAccordance()) ? JsonPolicyHelper.serialize(policy) : "");
        return model;
    }

    public static AiProjScanSettings verify(String json) throws GenericException {
        return call(() -> {
            ObjectMapper mapper = createObjectMapper();
            AiProjScanSettings res = mapper.readValue(json, AiProjScanSettings.class);
            if (StringUtils.isEmpty(res.getProjectName()))
                throw new IllegalArgumentException("ProjectName field is not defined or empty");
            if (null == res.getProgrammingLanguage())
                throw new IllegalArgumentException("ProgrammingLanguage field is not defined or empty");
            return res.fix();
        }, "JSON settings parse failed");
    }

    private static String serialize(AiProjScanSettings settings) throws GenericException {
        return call(
                () -> new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(settings.fix()),
                "JSON settings serialization failed");
    }

    /**
     * @param settingsJson JSON-defined AST settings
     * @return Minimized JSON-defined AST settings, i.e. without comments, formatting etc.
     * @throws GenericException
     */
    public static String minimize(@NonNull String settingsJson) throws GenericException {
        AiProjScanSettings settings = verify(settingsJson);
        return serialize(settings);
    }
}
