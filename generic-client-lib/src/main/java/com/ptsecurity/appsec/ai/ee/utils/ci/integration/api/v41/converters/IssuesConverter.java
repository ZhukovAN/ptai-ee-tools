package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v41.converters;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.*;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.server.v41.legacy.JSON;
import com.ptsecurity.appsec.ai.ee.server.v41.legacy.model.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryUsage;
import java.security.MessageDigest;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.joor.Reflect.on;

@Slf4j
public class IssuesConverter {
    private static final Map<IssueApprovalState, BaseIssue.ApprovalState> ISSUE_APPROVAL_STATE_MAP = new HashMap<>();
    private static final Map<String, BaseIssue.Type> ISSUE_TYPE_MAP = new HashMap<>();
    private static final Map<IssueLevel, BaseIssue.Level> ISSUE_LEVEL_MAP = new HashMap<>();
    private static final Map<V41VulnerabilityIssueScanMode, VulnerabilityIssue.ScanMode> SCAN_MODE_MAP = new HashMap<>();
    private static final Map<PolicyState, Policy.State> POLICY_STATE_MAP = new HashMap<>();
    private static final Map<V41ProgrammingLanguage, ScanResult.ScanSettings.Language> LANGUAGE_MAP = new HashMap<>();
    private static final Map<Stage, ScanResult.State> STATE_MAP = new HashMap<>();
    private static final Map<ScanResult.ScanSettings.Language, V41ProgrammingLanguage> REVERSE_LANGUAGE_MAP = new HashMap<>();

    static {
        ISSUE_APPROVAL_STATE_MAP.put(IssueApprovalState.None, BaseIssue.ApprovalState.NONE);
        ISSUE_APPROVAL_STATE_MAP.put(IssueApprovalState.Approval, BaseIssue.ApprovalState.APPROVAL);
        ISSUE_APPROVAL_STATE_MAP.put(IssueApprovalState.Discard, BaseIssue.ApprovalState.DISCARD);
        ISSUE_APPROVAL_STATE_MAP.put(IssueApprovalState.NotExist, BaseIssue.ApprovalState.NOT_EXIST);
        ISSUE_APPROVAL_STATE_MAP.put(IssueApprovalState.AutoApproval, BaseIssue.ApprovalState.AUTO_APPROVAL);

        ISSUE_TYPE_MAP.put(IssueType.Unknown.name(), BaseIssue.Type.UNKNOWN);
        ISSUE_TYPE_MAP.put(IssueType.Vulnerability.name(), BaseIssue.Type.VULNERABILITY);
        ISSUE_TYPE_MAP.put(IssueType.Weakness.name(), BaseIssue.Type.WEAKNESS);
        ISSUE_TYPE_MAP.put(IssueType.Configuration.name(), BaseIssue.Type.CONFIGURATION);
        ISSUE_TYPE_MAP.put(IssueType.Fingerprint.name(), BaseIssue.Type.SCA);
        ISSUE_TYPE_MAP.put(IssueType.BlackBox.name(), BaseIssue.Type.BLACKBOX);
        ISSUE_TYPE_MAP.put(IssueType.YaraMatch.name(), BaseIssue.Type.YARAMATCH);

        ISSUE_LEVEL_MAP.put(IssueLevel.None, BaseIssue.Level.NONE);
        ISSUE_LEVEL_MAP.put(IssueLevel.Potential, BaseIssue.Level.POTENTIAL);
        ISSUE_LEVEL_MAP.put(IssueLevel.Low, BaseIssue.Level.LOW);
        ISSUE_LEVEL_MAP.put(IssueLevel.Medium, BaseIssue.Level.MEDIUM);
        ISSUE_LEVEL_MAP.put(IssueLevel.High, BaseIssue.Level.HIGH);

        SCAN_MODE_MAP.put(V41VulnerabilityIssueScanMode.FromEntryPoint, VulnerabilityIssue.ScanMode.FROM_ENTRYPOINT);
        SCAN_MODE_MAP.put(V41VulnerabilityIssueScanMode.FromPublicProtected, VulnerabilityIssue.ScanMode.FROM_PUBLICPROTECTED);
        SCAN_MODE_MAP.put(null, VulnerabilityIssue.ScanMode.NONE);

        POLICY_STATE_MAP.put(PolicyState.None, Policy.State.NONE);
        POLICY_STATE_MAP.put(PolicyState.Rejected, Policy.State.REJECTED);
        POLICY_STATE_MAP.put(PolicyState.Confirmed, Policy.State.CONFIRMED);

        LANGUAGE_MAP.put(V41ProgrammingLanguage.JAVA, ScanResult.ScanSettings.Language.JAVA);
        LANGUAGE_MAP.put(V41ProgrammingLanguage.PHP, ScanResult.ScanSettings.Language.PHP);
        LANGUAGE_MAP.put(V41ProgrammingLanguage.CSHARP, ScanResult.ScanSettings.Language.CSHARP);
        LANGUAGE_MAP.put(V41ProgrammingLanguage.VB, ScanResult.ScanSettings.Language.VB);
        LANGUAGE_MAP.put(V41ProgrammingLanguage.GO, ScanResult.ScanSettings.Language.GO);
        LANGUAGE_MAP.put(V41ProgrammingLanguage.CPLUSPLUS, ScanResult.ScanSettings.Language.CPP);
        LANGUAGE_MAP.put(V41ProgrammingLanguage.PYTHON, ScanResult.ScanSettings.Language.PYTHON);
        LANGUAGE_MAP.put(V41ProgrammingLanguage.PLSQL, ScanResult.ScanSettings.Language.SQL);
        LANGUAGE_MAP.put(V41ProgrammingLanguage.JAVASCRIPT, ScanResult.ScanSettings.Language.JAVASCRIPT);
        LANGUAGE_MAP.put(V41ProgrammingLanguage.KOTLIN, ScanResult.ScanSettings.Language.KOTLIN);
        LANGUAGE_MAP.put(V41ProgrammingLanguage.SWIFT, ScanResult.ScanSettings.Language.SWIFT);
        LANGUAGE_MAP.put(V41ProgrammingLanguage.OBJECTIVEC, ScanResult.ScanSettings.Language.OBJECTIVEC);
        for (V41ProgrammingLanguage language : LANGUAGE_MAP.keySet())
            REVERSE_LANGUAGE_MAP.put(LANGUAGE_MAP.get(language), language);

        STATE_MAP.put(Stage.ABORTED, ScanResult.State.ABORTED);
        STATE_MAP.put(Stage.FAILED, ScanResult.State.FAILED);
        STATE_MAP.put(Stage.DONE, ScanResult.State.DONE);
        STATE_MAP.put(Stage.UNKNOWN, ScanResult.State.UNKNOWN);
        STATE_MAP.put(Stage.AUTOCHECK, ScanResult.State.UNKNOWN);
        STATE_MAP.put(Stage.ENQUEUED, ScanResult.State.UNKNOWN);
        STATE_MAP.put(Stage.FINALIZE, ScanResult.State.UNKNOWN);
        STATE_MAP.put(Stage.INITIALIZE, ScanResult.State.UNKNOWN);
        STATE_MAP.put(Stage.PRECHECK, ScanResult.State.UNKNOWN);
        STATE_MAP.put(Stage.SCAN, ScanResult.State.UNKNOWN);
        STATE_MAP.put(Stage.VFSSETUP, ScanResult.State.UNKNOWN);
    }

    /**
     * Method converts PT AI v.4.0 API scan settings to API version independent scan settings
     * @param scanSettings PT AI v.4.0 API scan settings
     * @return PT AI API version independent scan settings
     */
    public static ScanResult.ScanSettings convert(@NonNull final V41ScanSettings scanSettings) {
        ScanResult.ScanSettings res = ScanResult.ScanSettings.builder()
                .id(Objects.requireNonNull(scanSettings.getId(), "Scan settings ID is null"))
                .build();

        res.setUrl(scanSettings.getSite());
        res.setCustomParameters(scanSettings.getCustomParameters());
        res.setJavaParameters(scanSettings.getJavaParameters());

        res.setAutocheckAfterScan(scanSettings.getRunAutocheckAfterScan());
        res.setDownloadDependencies(scanSettings.getIsDownloadDependencies());
        res.setUseEntryAnalysisPoint(scanSettings.getIsUseEntryAnalysisPoint());
        res.setUsePublicAnalysisMethod(scanSettings.getIsUsePublicAnalysisMethod());
        res.setUnpackUserPackages(scanSettings.getIsUnpackUserPackages());


        ScanResult.ScanSettings.Language language = LANGUAGE_MAP.get(Objects.requireNonNull(scanSettings.getProgrammingLanguage(), "Scan settings programming language is null"));
        res.setLanguage(Objects.requireNonNull(language, "Unknown programming language " + scanSettings.getProgrammingLanguage()));

        String scanAppTypeString = scanSettings.getScanAppType();
        List<String> scanAppTypes = parseCommaSeparatedValues(scanAppTypeString);
        if (null == scanAppTypes) return res;
        for (String scanAppType : scanAppTypes) {
            if (ScanAppType.CONFIGURATION.name().equalsIgnoreCase(scanAppType))
                res.getEngines().add(ScanResult.ScanSettings.Engine.CONFIGURATION);
            else if (ScanAppType.FINGERPRINT.name().equalsIgnoreCase(scanAppType))
                res.getEngines().add(ScanResult.ScanSettings.Engine.FINGERPRINT);
            else if (ScanAppType.JAVA.name().equalsIgnoreCase(scanAppType))
                res.getEngines().add(ScanResult.ScanSettings.Engine.AI);
            else if (ScanAppType.CSHARP.name().equalsIgnoreCase(scanAppType))
                res.getEngines().add(ScanResult.ScanSettings.Engine.AI);
            else if (ScanAppType.PHP.name().equalsIgnoreCase(scanAppType))
                res.getEngines().add(ScanResult.ScanSettings.Engine.AI);
            else if (ScanAppType.PMTAINT.name().equalsIgnoreCase(scanAppType)) {
                if (Objects.requireNonNull(scanSettings.getUsePmAnalysis(), "usePmAnalysis is null"))
                    res.getEngines().add(ScanResult.ScanSettings.Engine.PM);
                if (Objects.requireNonNull(scanSettings.getUseTaintAnalysis(), "useTaintAnalysis is null"))
                    res.getEngines().add(ScanResult.ScanSettings.Engine.TAINT);
            } else if (ScanAppType.BLACKBOX.name().equalsIgnoreCase(scanAppType))
                res.getEngines().add(ScanResult.ScanSettings.Engine.BLACKBOX);
            else if (ScanAppType.DEPENDENCYCHECK.name().equalsIgnoreCase(scanAppType))
                res.getEngines().add(ScanResult.ScanSettings.Engine.DC);
        }
        return res;
    }

    /**
     * Method converts C#-style TimeSpan serialized string
     * (https://docs.microsoft.com/en-us/dotnet/standard/base-types/standard-timespan-format-strings)
     * to Java 8 Duration instance
     * @param value TimeSpan serialized value like "00:05:06.2269294"
     * @return Java 8 Duration instance
     */
    protected static Duration parseDuration(@NonNull final String value) {
        final Pattern pattern = Pattern.compile("(-)?([\\d]+\\.)?([\\d]{2}:[\\d]{2}:[\\d]{2})(\\.[\\d]+)?");
        Matcher matcher = pattern.matcher(value);
        if (!matcher.matches()) throw new IllegalArgumentException("Duration " + value + " parse failed");
        Duration res = Duration.between(LocalTime.MIN, LocalTime.parse(matcher.group(3), DateTimeFormatter.ISO_LOCAL_TIME));
        // Let's work with days
        if (StringUtils.isNotEmpty(matcher.group(2))) {
            String daysStr = StringUtils.stripEnd(matcher.group(2), ".");
            res = res.plusDays(Integer.parseInt(daysStr));
        }
        if (StringUtils.isNotEmpty(matcher.group(4))) {
            String fractionStr = StringUtils.stripStart(matcher.group(4), ".");
            if (7 < fractionStr.length())
                fractionStr = StringUtils.left(fractionStr, 7);
            else if (7 > fractionStr.length())
                fractionStr = StringUtils.rightPad(fractionStr, 7, "0");
            res = res.plusNanos(Integer.parseInt(fractionStr) * 100L);
        }
        if (StringUtils.isNotEmpty(matcher.group(1))) res = res.negated();
        return res;
    }

    /**
     * Method converts PT AI v.3.6 API scan result and issues model pair to API version independent scan result
     * @param scanResult PT AI v.3.6 API scan result that contains scan statistic
     * @param modelFiles PT AI v.3.6 API scan issues list with detailed information about vulnerabilities found
     * @param scanSettings PT AI v.3.6 API scan settings
     * @return PT AI API version independent scan results instance
     */
    public static ScanResult convert(
            @NonNull final String projectName,
            @NonNull final com.ptsecurity.appsec.ai.ee.server.v41.legacy.model.ScanResult scanResult,
            @NonNull final Map<Reports.Locale, File> modelFiles,
            @NonNull final V41ScanSettings scanSettings,
            @NonNull final String ptaiUrl,
            @NonNull final Map<ServerVersionTasks.Component, String> versions) {
        ScanResult res = new ScanResult();
        convertInto(projectName, scanResult, scanSettings, versions, res);
        res.setApiVersion(ScanBrief.ApiVersion.V41);
        res.setPtaiServerUrl(ptaiUrl);

        // As there's no localization in metadatas, use english model as source
        IssuesModel model = null;
        // Parse localizedModels and extract titles and descriptions from them
        Map<String, Map<Reports.Locale, ScanResult.Strings>> dictionary = new HashMap<>();
        // At this point we have ScanResult that is initialized with vulnerability list. But these
        // vulnerabilities have titleId field that points nowhere. So we need to create localized
        // descriptions for all of them
        for (Reports.Locale locale : modelFiles.keySet()) {
            IssuesModel localizedModel = parseIssuesModelStream(modelFiles.get(locale));
            // Save first model as a metadata source. As metadata is not i18n-ed, there's
            // no difference what locale will be used
            if (null == model) model = localizedModel;
            if (null == localizedModel.getDescriptions() || localizedModel.getDescriptions().isEmpty()) continue;
            Map<String, V41IssueDescriptionModel> descriptions = localizedModel.getDescriptions();
            for (V41IssueDescriptionModel idm : descriptions.values()) {
                if (null == idm.getDescriptionValue() || StringUtils.isEmpty(idm.getDescriptionValue().getHeader())) continue;
                // Store localized title to dictionary
                Map<Reports.Locale, ScanResult.Strings> values = dictionary.computeIfAbsent(idm.getIdentity(), l -> new HashMap<>());
                values.put(locale, ScanResult.Strings.builder()
                        .title(idm.getDescriptionValue().getHeader())
                        .description(idm.getDescriptionValue().getDescription())
                        .build());
                // Store localized description to the same dictionary, but use different key
                if (StringUtils.isEmpty(idm.getDescriptionValue().getDescription()))
                    log.warn("Vulnerability {} have no description", idm.getDescriptionValue().getHeader());
            }
        }

        if (null == model) {
            log.warn("Issues model not found");
            return null;
        }

        Map<String, IssueBaseMetadata> metadataMap = new HashMap<>();
        if (null != model.getMetadatas())
            for (IssueBaseMetadata metadata : model.getMetadatas().values())
                metadataMap.put(metadata.getKey(), metadata);
        if (null != model.getIssues()) {
            for (IssueBase issue : model.getIssues()) {
                List<BaseIssue> issues = convert(issue, metadataMap, dictionary);
                if (null != issues && !issues.isEmpty())
                    res.getIssues().addAll(issues);
                else
                    log.warn("Issue {} format conversion failed", issue);
            }
        }
        // Issue format conversion sets type field to value that can be safely mapped to localized description
        for (BaseIssue issue : res.getIssues()) {
            String key = issue.getTypeId();
            res.getI18n().put(issue.getIssueTypeKey(), dictionary.get(key));
        }
        res.setIssuesParseOk(model != EMPTY_ISSUES_MODEL);
        return res;
    }

    public static ScanBrief.Statistics convert(
            final ScanResultStatistic statistic,
            @NonNull final com.ptsecurity.appsec.ai.ee.server.v41.legacy.model.ScanResult scanResult) {
        if (null == statistic) return null;

        // PT AI REST API uses UTC date / time representation, but without "Z" letter at the end of ISO 8601 representation
        String scanDateString = Objects.requireNonNull(scanResult.getScanDate(), "Scan result date is null");
        if (!StringUtils.endsWith(scanDateString, "Z")) scanDateString = scanDateString + "Z";
        ZonedDateTime zonedScanDate = ZonedDateTime.parse(scanDateString, DateTimeFormatter.ISO_DATE_TIME);

        String scanDurationString = Objects.requireNonNull(statistic.getScanDuration(), "Scan duration is null");
        Duration scanDuration = parseDuration(scanDurationString);

        return ScanBrief.Statistics.builder()
                .scanDateIso8601(zonedScanDate.format(DateTimeFormatter.ISO_DATE_TIME))
                .scanDurationIso8601(scanDuration.toString())
                .scannedFileCount(Objects.requireNonNull(statistic.getScannedFileCount(), "Get scanned file count statistic is null"))
                .scannedUrlCount(Objects.requireNonNull(statistic.getScannedUrlCount(), "Get scanned URL count statistic is null"))
                .totalFileCount(Objects.requireNonNull(statistic.getTotalFileCount(), "Get total file count statistic is null"))
                .totalUrlCount(Objects.requireNonNull(statistic.getTotalUrlCount(), "Get total URL count statistic is null"))
                .build();
    }

    public static VulnerabilityIssue.BestPlaceToFix convert(final V41BestPlaceToFix bpf) {
        if (null == bpf) return null;
        return VulnerabilityIssue.BestPlaceToFix.builder()
                .place(convert(bpf.getPlace()))
                .build();
    }

    public static BaseSourceIssue.Place convert(final V41Place place) {
        if (null == place) return null;
        return BaseSourceIssue.Place.builder()
                .file(Objects.requireNonNull(place.getFile()))
                .value(place.getValue())
                .beginColumn(Objects.requireNonNull(place.getBeginColumn()))
                .endColumn(Objects.requireNonNull(place.getEndColumn()))
                .beginLine(Objects.requireNonNull(place.getBeginLine()))
                .endLine(Objects.requireNonNull(place.getEndLine()))
                .build();
    }

    /**
     * Method converts PT AI v.3.6 CVSS data to version independent CVSS instance
     * @param cvss PT AI v.3.6 CVSS data that is to be converted
     * @return PT AI API version independent CVSS instance
     */
    public static ScaIssue.Cvss convert(final V41CvssMetadata cvss) {
        if (null == cvss) return null;
        return ScaIssue.Cvss.builder()
                .base(cvss.getBase())
                .baseScore(cvss.getBaseScore())
                .temp(cvss.getTemp())
                .tempScore(cvss.getTempScore())
                .build();
    }

    /**
     * Method copies generic fields data from PT AI v.3.6 issue to version-independent issue
     * @param source PT AI v.3.6 base issue where fields data is copied from
     * @param destination PT AI API version independent base issue
     */
    protected static void setBaseFields(
            @NonNull final IssueBase source,
            @NonNull final BaseIssue destination,
            @NonNull final Map<String, Map<Reports.Locale, ScanResult.Strings>> dictionary) {
        destination.setId(source.getId());
        destination.setGroupId(source.getGroupId());
        destination.setLevel(ISSUE_LEVEL_MAP.get(source.getLevel()));

        destination.setApprovalState(ISSUE_APPROVAL_STATE_MAP.get(source.getApprovalState()));
        destination.setFavorite(source.getIsFavorite());
        destination.setSuppressed(source.getIsSuppressed());
        destination.setSuspected(source.getIsSuspected());
        destination.setNewInScanResultId(source.getIsNewInScanResultId());

        destination.setTypeId(source.getType());
    }

    /**
     * Method converts string of a comma-separated values to list of strings. Each value is trimmed prior to being added
     * @param values Comma-separated string
     * @return List of String values
     */
    protected static List<String> parseCommaSeparatedValues(final String values) {
        if (StringUtils.isEmpty(values)) return null;
        String[] valuesArray = values.split("[, ]+");
        List<String> res = Arrays.stream(valuesArray).filter(StringUtils::isNotEmpty).map(String::trim).collect(Collectors.toList());
        return res.isEmpty() ? null : res;
    }

    /**
     * Method checks if object have method of a given name that accepts List parameter
     * @param object Object to check for method existence
     * @param name Method name
     * @return True if object have method
     */
    protected static boolean haveStringListSetter(@NonNull final Object object, @NonNull final String name) {
        return haveAccessor(object, name, List.class);
    }

    /**
     * Method checks if object have method of a given name that accepts single string parameter
     * @param object Object to check for method existence
     * @param name Method name
     * @return True if object have method
     */
    protected static boolean haveStringGetter(@NonNull final Object object, @NonNull final String name) {
        return haveAccessor(object, name);
    }

    /**
     * Method checks if object have method of a given name that accepts parameter of desired class
     * @param object Object to check for method existence
     * @param name Method name
     * @param clazz Parameter class or null if checking for aa parameterless method
     * @return True if object have method
     */
    protected static boolean haveAccessor(@NonNull final Object object, @NonNull final String name, Class<?> clazz) {
        try {
            if (null != clazz)
                object.getClass().getMethod(name, clazz);
            else
                object.getClass().getMethod(name);
        } catch (NoSuchMethodException e) {
            return false;
        }
        return true;
    }

    /**
     * Method checks if object have parameterless method of a given name
     * @param object Object to check for method existence
     * @param name Method name
     * @return True if object have method
     */
    protected static boolean haveAccessor(@NonNull final Object object, @NonNull final String name) {
        return haveAccessor(object, name, null);
    }

    /**
     * Method reads metadata (i.e. CWE, OWASP, PCI DSS etc. IDs) fields and writes them into corresponding issue fields
     * @param metadata Issue metadata
     * @param issue Issue where metadata fields are to be written into
     */
    protected static void applyMetadata(@NonNull final IssueBaseMetadata metadata, @NonNull final BaseIssue issue) {
        final List<Pair<String, String>> methodPairs = Arrays.asList(
                new ImmutablePair<>("setCweId", "getCweId"),
                new ImmutablePair<>("setOwaspId", "getOwaspId"),
                new ImmutablePair<>("setPciDssId", "getPciId"),
                new ImmutablePair<>("setNistId", "getNist"));

        for (Pair<String, String> methodPair : methodPairs) {
            if (!haveStringGetter(metadata, methodPair.getRight())) continue;
            if (!haveStringListSetter(issue, methodPair.getLeft())) continue;
            String value = on(metadata).call(methodPair.getRight()).get();
            List<String> values = parseCommaSeparatedValues(value);
            on(issue).call(methodPair.getLeft(), values);
        }
        if (haveAccessor(metadata, "getCveId") && haveAccessor(issue, "setCveId", String.class)) {
            String value = on(metadata).call("getCveId").get();
            on(issue).call("setCveId", value);
        }
        if (haveAccessor(metadata, "getCvss") && haveAccessor(issue, "setCvss", ScaIssue.Cvss.class)) {
            V41CvssMetadata value = on(metadata).call("getCvss").get();
            on(issue).call("setCvss", convert(value));
        }
        if (haveAccessor(metadata, "getLevel") && haveAccessor(issue, "setLevel", BaseIssue.Level.class)) {
            IssueLevel value = on(metadata).call("getLevel").get();
            on(issue).call("setLevel", ISSUE_LEVEL_MAP.get(value));
        }
    }

    /**
     * Method converts PT AI v.3.6 API issue to list of API version independent vulnerabilities
     * @param issueBase Base information about vulnerability. Exact descendant iccue class type dependes
     *                  on a propertyClass field value
     * @param metadataMap Map of all issues metadatas. Used to enrich result issue with OWASP, CWE, NIST etc. IDs
     * @param dictionary Localized map of all issues descriptions. Used to enrich result issue with title
     * @return PT AI API version independent vulnerability instance
     */
    protected static List<BaseIssue> convert(
            @NonNull final IssueBase issueBase,
            @NonNull final Map<String, IssueBaseMetadata> metadataMap,
            @NonNull final Map<String, Map<Reports.Locale, ScanResult.Strings>> dictionary) {
        // Issue description linked to issue via IssueBase:type - IssueDescriptionModel:identity
        // association. So let's create single localized dictionary of vulnerability titles

        // PT AI API uses string representation for issue class field
        IssueType issueType = IssueType.valueOf(issueBase.getPropertyClass());
        // All issues except SCA ones are linked to metadata and descriptions using type field.
        // SCA uses array of fingerprint IDs and those are to be processed separately
        IssueBaseMetadata baseMetadata = null;

        if (IssueType.Fingerprint != issueType) {
            baseMetadata = metadataMap.get(issueBase.getType());
            if (null == baseMetadata) {
                log.warn("Skipping issue {} as there were no metadata found", issueBase.getId());
                log.trace(issueBase.toString());
                return null;
            }
            if (!dictionary.containsKey(issueBase.getType())) {
                log.warn("Skipping issue {} as there were no description found", issueBase.getId());
                log.trace(issueBase.toString());
                return null;
            }
        }

        if (IssueType.BlackBox == issueType && issueBase instanceof V41BlackBoxIssue) {
                V41BlackBoxIssue issue = (V41BlackBoxIssue) issueBase;

                BlackBoxIssue res = new BlackBoxIssue();
                setBaseFields(issue, res, dictionary);
                applyMetadata(baseMetadata, res);

                return Collections.singletonList(res);
        } else if (IssueType.Configuration == issueType && issueBase instanceof V41ConfigurationIssue) {
            V41ConfigurationIssue issue = (V41ConfigurationIssue) issueBase;

            ConfigurationIssue res = new ConfigurationIssue();
            setBaseFields(issue, res, dictionary);
            applyMetadata(baseMetadata, res);

            res.setVulnerableExpression(convert(issue.getVulnerableExpression()));
            res.setCurrentValue(issue.getExistingValue());
            res.setRecommendedValue(issue.getRecommendedValue());

            return Collections.singletonList(res);
        } else if (IssueType.Fingerprint == issueType) {
            V41FingerprintIssue issue = (V41FingerprintIssue) issueBase;

            List<String> fingerprintIds = issue.getFingerprintIds();
            if (null == fingerprintIds || fingerprintIds.isEmpty()) return null;
            List<BaseIssue> scaIssues = new ArrayList<>();
            for (String fingerprintId : fingerprintIds) {
                baseMetadata = metadataMap.get(fingerprintId);
                if (null == baseMetadata) {
                    log.warn("Skipping issue {} as there were no metadata found", issueBase.getId());
                    log.trace(issueBase.toString());
                    continue;
                }
                if (!dictionary.containsKey(fingerprintId)) {
                    log.warn("Skipping issue {} as there were no description found", issueBase.getId());
                    log.trace(issueBase.toString());
                    continue;
                }
                ScaIssue res = new ScaIssue();
                // All vulnerabilities except fingerprint ones are linked to their descriptions
                // using vulnerability.type. Fingerprint vulnerabilities have null value in
                // type field and linked using fingerprintId instead. Let's init it with fingerprintId
                // to avoid setBaseFields change
                issue.setType(fingerprintId);
                setBaseFields(issue, res, dictionary);
                // As single v41FingerprintIssue may have multiple fingerprint IDs
                // PT AI looks these IDs for maximum severity level and assigns it
                // to issue. But as we decide to create individual ScaIssue for
                // each fingerprintId, we need to fix level by applying actual level
                // value from metadata linked to this fingerprint Id
                applyMetadata(baseMetadata, res);
                res.setFingerprintId(fingerprintId);
                res.setComponentName(issue.getComponentName());
                res.setComponentVersion(issue.getComponentVersion());
                if (null != issue.getVulnerableExpression())
                    res.setFile(issue.getVulnerableExpression().getFile());
                // SCA-related descriptions are ugly: sometimes they do contain CVE ID only. Let's replace it with more descriptive data
                for (Reports.Locale locale : Reports.Locale.values()) {
                    String title = Reports.Locale.RU == locale
                            ? "Уязвимый компонент" : "Vulnerable component";
                    title += " " + issue.getComponentName() + " " + issue.getComponentVersion();
                    if (StringUtils.isNotEmpty(res.getCveId()))
                        title += " (" + res.getCveId() + ")";
                    dictionary.get(fingerprintId).get(locale).setTitle(title);
                }
                // As single file may be subject to a multiple vulnerabilities, we need to
                // create separate issue for each fingerprint and use metadata values
                scaIssues.add(res);
            }
            return scaIssues;
        } else if (IssueType.Unknown == issueType) {
            V41UnknownIssue issue = (V41UnknownIssue) issueBase;

            UnknownIssue res = new UnknownIssue();
            setBaseFields(issue, res, dictionary);
            return Collections.singletonList(res);
        } else if (IssueType.Vulnerability == issueType) {
            V41VulnerabilityIssue issue = (V41VulnerabilityIssue) issueBase;

            VulnerabilityIssue res = new VulnerabilityIssue();
            setBaseFields(issue, res, dictionary);
            applyMetadata(baseMetadata, res);

            res.setSecondOrder(issue.getIsSecondOrder());
            res.setPvf(issue.getFunction());
            res.setVulnerableExpression(convert(issue.getVulnerableExpression()));
            res.setEntryPoint(convert(issue.getEntryPoint()));

            List<V41Place> entries = issue.getTaintDataEntries();
            if (null != entries && !entries.isEmpty())
                res.setTaintDataEntries(entries.stream().map(IssuesConverter::convert).collect(Collectors.toList()));
            entries = issue.getDataTrace();
            if (null != entries && !entries.isEmpty())
                res.setDataTrace(entries.stream().map(IssuesConverter::convert).collect(Collectors.toList()));

            res.setScanMode(SCAN_MODE_MAP.getOrDefault(issue.getScanMode(), VulnerabilityIssue.ScanMode.FROM_OTHER));
            res.setBpf(convert(issue.getBestPlaceToFix()));
            res.setConditions(issue.getAdditionalConditions());

            return Collections.singletonList(res);
        } else if (IssueType.Weakness == issueType) {
            V41WeaknessIssue issue = (V41WeaknessIssue) issueBase;

            WeaknessIssue res = new WeaknessIssue();
            setBaseFields(issue, res, dictionary);
            applyMetadata(baseMetadata, res);
            res.setVulnerableExpression(convert(issue.getVulnerableExpression()));

            return Collections.singletonList(res);
        } else if (IssueType.YaraMatch == issueType) {
            V41YaraMatchIssue issue = (V41YaraMatchIssue) issueBase;

            YaraMatchIssue res = new YaraMatchIssue();
            setBaseFields(issue, res, dictionary);
            return Collections.singletonList(res);
        } else
            return null;
    }

    @NonNull
    public static V41ProgrammingLanguage convertLanguage(@NonNull final ScanResult.ScanSettings.Language language) {
        V41ProgrammingLanguage res = REVERSE_LANGUAGE_MAP.get(language);
        return null == res ? V41ProgrammingLanguage.NONE : res;
    }

    public static final IssuesModel EMPTY_ISSUES_MODEL = new IssuesModel();

    /**
     * Method reads data from stream and deserializes it to PT AI v.3.6 IssuesModel instance
     * @param data Serialized stream of PT AI v.3.6 API data issues list with detailed information about vulnerabilities found
     * @return Deserialized IssuesModel instance
     */
    @SneakyThrows
    protected static IssuesModel parseIssuesModelStream(@NonNull final File data) {
        JSON parser = new JSON();
        MemoryUsage usage = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();
        try (InputStream is = new FileInputStream(data); Reader reader = new InputStreamReader(is, UTF_8)) {
            log.debug("JVM heap memory use before parse {} / {}", FileCollector.bytesToString(usage.getUsed()), FileCollector.bytesToString(usage.getMax()));
            log.debug("Parse started at {}", Instant.now());
            IssuesModel res = parser.getGson().fromJson(reader, IssuesModel.class);
            log.debug("Parse finished at {}", Instant.now());
            log.debug("JVM heap memory use after parse {} / {}", FileCollector.bytesToString(usage.getUsed()), FileCollector.bytesToString(usage.getMax()));
            return res;
        } catch (OutOfMemoryError e) {
            log.error("IssuesModel file parse failed due to lack of heap memory", e);
            return EMPTY_ISSUES_MODEL;
        }
    }

    /**
     * Method collects
     * @param projectName
     * @param scanResult
     * @param scanSettings
     * @param versions
     * @param destination
     */
    public static void convertInto(
            @NonNull final String projectName,
            @NonNull final com.ptsecurity.appsec.ai.ee.server.v41.legacy.model.ScanResult scanResult,
            @NonNull final V41ScanSettings scanSettings,
            @NonNull final Map<ServerVersionTasks.Component, String> versions,
            @NonNull final ScanBrief destination) {
        destination.setPtaiServerVersion(versions.get(ServerVersionTasks.Component.AIE));
        destination.setPtaiAgentVersion(versions.get(ServerVersionTasks.Component.AIC));
        destination.setId(Objects.requireNonNull(scanResult.getId(), "Scan result ID is null"));
        destination.setProjectId(Objects.requireNonNull(scanResult.getProjectId(), "Scan result project ID is null"));
        destination.setProjectName(projectName);
        destination.setScanSettings(convert(scanSettings));

        ScanResultStatistic statistic = Objects.requireNonNull(scanResult.getStatistic(), "Scan result statistics is null");
        destination.setStatistics(convert(statistic, scanResult));

        ScanProgress progress = Objects.requireNonNull(scanResult.getProgress(), "Scan result progress is null");
        destination.setState(STATE_MAP.get(progress.getStage()));

        destination.setPolicyState(POLICY_STATE_MAP.get(statistic.getPolicyState()));
    }

    public static ScanBrief convert(
            @NonNull final String projectName,
            @NonNull final com.ptsecurity.appsec.ai.ee.server.v41.legacy.model.ScanResult scanResult,
            @NonNull final V41ScanSettings scanSettings,
            @NonNull final String ptaiUrl,
            @NonNull final Map<ServerVersionTasks.Component, String> versions) {
        ScanBrief res = new ScanBrief();
        convertInto(projectName, scanResult, scanSettings, versions, res);
        res.setApiVersion(ScanBrief.ApiVersion.V41);
        res.setPtaiServerUrl(ptaiUrl);
        return res;
    }

    public static Policy.State convert(@NonNull final PolicyState policyState) {
        return POLICY_STATE_MAP.get(policyState);
    }
}
