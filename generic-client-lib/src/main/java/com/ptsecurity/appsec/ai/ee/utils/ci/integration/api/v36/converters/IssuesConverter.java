package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.converters;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.JSON;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.*;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.*;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.FileCollector;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.time.Duration;
import java.time.LocalTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.joor.Reflect.on;

@Slf4j
public class IssuesConverter {
    private static final String PTAI_API_VERSION = "3.6";

    private static final Map<IssueApprovalState, BaseIssue.ApprovalState> ISSUE_APPROVAL_STATE_MAP = new HashMap<>();
    private static final Map<String, BaseIssue.Type> ISSUE_TYPE_MAP = new HashMap<>();
    private static final Map<IssueLevel, BaseIssue.Level> ISSUE_LEVEL_MAP = new HashMap<>();
    private static final Map<V36VulnerabilityIssueScanMode, VulnerabilityIssue.ScanMode> SCAN_MODE_MAP = new HashMap<>();
    private static final Map<PolicyState, Policy.PolicyState> POLICY_STATE_MAP = new HashMap<>();
    private static final Map<V36ProgrammingLanguage, ScanResult.ScanSettings.Language> LANGUAGE_MAP = new HashMap<>();
    private static final Map<Stage, ScanResult.State> STATE_MAP = new HashMap<>();
    private static final Map<ScanResult.ScanSettings.Language, V36ProgrammingLanguage> REVERSE_LANGUAGE_MAP = new HashMap<>();

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

        SCAN_MODE_MAP.put(V36VulnerabilityIssueScanMode.FromEntryPoint, VulnerabilityIssue.ScanMode.FROM_ENTRYPOINT);
        SCAN_MODE_MAP.put(V36VulnerabilityIssueScanMode.FromPublicProtected, VulnerabilityIssue.ScanMode.FROM_PUBLICPROTECTED);

        // Bug https://jira.ptsecurity.com/browse/AI-4866 with swapped
        // confirmed / rejected states fixed and will be included in 3.7
        POLICY_STATE_MAP.put(PolicyState.NONE, Policy.PolicyState.NONE);
        POLICY_STATE_MAP.put(PolicyState.CONFIRMED, Policy.PolicyState.REJECTED);
        POLICY_STATE_MAP.put(PolicyState.REJECTED, Policy.PolicyState.CONFIRMED);

        LANGUAGE_MAP.put(V36ProgrammingLanguage.JAVA, ScanResult.ScanSettings.Language.JAVA);
        LANGUAGE_MAP.put(V36ProgrammingLanguage.PHP, ScanResult.ScanSettings.Language.PHP);
        LANGUAGE_MAP.put(V36ProgrammingLanguage.CSHARP, ScanResult.ScanSettings.Language.CSHARP);
        LANGUAGE_MAP.put(V36ProgrammingLanguage.VB, ScanResult.ScanSettings.Language.VB);
        LANGUAGE_MAP.put(V36ProgrammingLanguage.GO, ScanResult.ScanSettings.Language.GO);
        LANGUAGE_MAP.put(V36ProgrammingLanguage.CPLUSPLUS, ScanResult.ScanSettings.Language.CPP);
        LANGUAGE_MAP.put(V36ProgrammingLanguage.PYTHON, ScanResult.ScanSettings.Language.PYTHON);
        LANGUAGE_MAP.put(V36ProgrammingLanguage.PLSQL, ScanResult.ScanSettings.Language.SQL);
        LANGUAGE_MAP.put(V36ProgrammingLanguage.JAVASCRIPT, ScanResult.ScanSettings.Language.JS);
        LANGUAGE_MAP.put(V36ProgrammingLanguage.KOTLIN, ScanResult.ScanSettings.Language.KOTLIN);
        LANGUAGE_MAP.put(V36ProgrammingLanguage.SWIFT, ScanResult.ScanSettings.Language.SWIFT);
        LANGUAGE_MAP.put(V36ProgrammingLanguage.OBJECTIVEC, ScanResult.ScanSettings.Language.OBJECTIVEC);
        for (V36ProgrammingLanguage language : LANGUAGE_MAP.keySet())
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
     * Method converts PT AI v.3.6 API scan settings to API version independent scan settings
     * @param scanSettings PT AI v.3.6 API scan settings
     * @return PT AI API version independent scan settings
     */
    public static ScanResult.ScanSettings convert(@NonNull final V36ScanSettings scanSettings) {
        ScanResult.ScanSettings res = ScanResult.ScanSettings.builder()
                .id(Objects.requireNonNull(scanSettings.getId(), "Scan settings ID is null"))
                .build();

        res.setUrl(scanSettings.getSite());
        res.setCustomParameters(scanSettings.getCustomParameters());
        res.setJavaParameters(scanSettings.getJavaParameters());

        res.setAutocheckAfterScan(scanSettings.getRunAutocheckAfterScan());
        res.setDownloadDependencies(scanSettings.getIsDownloadDependencies());
        res.setUseIncrementalScan(scanSettings.getUseIncrementalScan());
        res.setUseEntryAnalysisPoint(scanSettings.getIsUseEntryAnalysisPoint());
        res.setUsePublicAnalysisMethod(scanSettings.getIsUsePublicAnalysisMethod());
        res.setUnpackUserPackages(scanSettings.getIsUnpackUserPackages());


        ScanResult.ScanSettings.Language language = LANGUAGE_MAP.get(Objects.requireNonNull(scanSettings.getProgrammingLanguage(), "Scan settings programming language is null"));
        res.setLanguage(Objects.requireNonNull(language, "Unknown programming language " + scanSettings.getProgrammingLanguage()));

        String scanAppTypeString = scanSettings.getScanAppType();
        List<String> scanAppTypes = parseCommaSeparatedValues(scanAppTypeString);
        if (null == scanAppTypes) return res;
        for (String scanAppType : scanAppTypes) {
            if (ScanAppType.Configuration.name().equals(scanAppType))
                res.getEngines().add(ScanResult.ScanSettings.Engine.CONFIGURATION);
            else if (ScanAppType.Fingerprint.name().equals(scanAppType))
                res.getEngines().add(ScanResult.ScanSettings.Engine.FINGERPRINT);
            else if (ScanAppType.Java.name().equals(scanAppType))
                res.getEngines().add(ScanResult.ScanSettings.Engine.AI);
            else if (ScanAppType.CSharp.name().equals(scanAppType))
                res.getEngines().add(ScanResult.ScanSettings.Engine.AI);
            else if (ScanAppType.PHP.name().equals(scanAppType))
                res.getEngines().add(ScanResult.ScanSettings.Engine.AI);
            else if (ScanAppType.PmTaint.name().equals(scanAppType)) {
                if (Objects.requireNonNull(scanSettings.getUsePmAnalysis(), "usePmAnalysis is null"))
                    res.getEngines().add(ScanResult.ScanSettings.Engine.PM);
                if (Objects.requireNonNull(scanSettings.getUseTaintAnalysis(), "useTaintAnalysis is null"))
                    res.getEngines().add(ScanResult.ScanSettings.Engine.TAINT);
            } else if (ScanAppType.BlackBox.name().equals(scanAppType))
                res.getEngines().add(ScanResult.ScanSettings.Engine.BLACKBOX);
            else if (ScanAppType.DependencyCheck.name().equals(scanAppType))
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
     * @param model PT AI v.3.6 API scan issues list with detailed information about vulnerabilities found
     * @param scanSettings PT AI v.3.6 API scan settings
     * @return PT AI API version independent scan results instance
     */
    public static ScanResult convert(
            @NonNull final com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult scanResult,
            @NonNull final IssuesModel model,
            @NonNull final V36ScanSettings scanSettings) {
        ScanResult res = new ScanResult();
        convertInto(scanResult, scanSettings, res);

        Map<String, IssueBaseMetadata> metadataMap = new HashMap<>();
        if (null != model.getMetadatas())
            for (IssueBaseMetadata metadata : model.getMetadatas().values())
                metadataMap.put(metadata.getKey(), metadata);
        Map<String, IssueDescriptionModel> descriptionsMap = new HashMap<>();
        if (null != model.getDescriptions())
            for (IssueDescriptionModel metadata : model.getDescriptions().values())
                descriptionsMap.put(metadata.getIdentity(), metadata);
        if (null != model.getIssues()) {
            for (IssueBase issue : model.getIssues()) {
                List<BaseIssue> issues = convert(issue, metadataMap, descriptionsMap);
                if (null != issues && !issues.isEmpty())
                    res.getIssues().addAll(issues);
                else
                    System.out.println(issue);
            }
        }
        res.setIssuesParseState(model != EMPTY_ISSUES_MODEL);
        return res;
    }

    public static ScanResult.Statistic convert(
            final ScanResultStatistic statistic,
            @NonNull final com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult scanResult) {
        if (null == statistic) return null;

        // PT AI REST API uses UTC date / time representation, but without "Z" letter at the end of ISO 8601 representation
        String scanDateString = Objects.requireNonNull(scanResult.getScanDate(), "Scan result date is null");
        if (!StringUtils.endsWith(scanDateString, "Z")) scanDateString = scanDateString + "Z";
        ZonedDateTime zonedScanDate = ZonedDateTime.parse(scanDateString, DateTimeFormatter.ISO_DATE_TIME);

        String scanDurationString = Objects.requireNonNull(statistic.getScanDuration(), "Scan duration is null");
        Duration scanDuration = parseDuration(scanDurationString);

        return ScanResult.Statistic.builder()
                .scanDateIso8601(zonedScanDate.format(DateTimeFormatter.ISO_DATE_TIME))
                .scanDurationIso8601(scanDuration.toString())
                .scannedFileCount(Objects.requireNonNull(statistic.getScannedFileCount(), "Get scanned file count statistic is null"))
                .scannedUrlCount(Objects.requireNonNull(statistic.getScannedUrlCount(), "Get scanned URL count statistic is null"))
                .totalFileCount(Objects.requireNonNull(statistic.getTotalFileCount(), "Get total file count statistic is null"))
                .totalUrlCount(Objects.requireNonNull(statistic.getTotalUrlCount(), "Get total URL count statistic is null"))
                .build();
    }

    public static VulnerabilityIssue.Exploit convert(final V36Exploit exploit) {
        if (null == exploit) return null;
        VulnerabilityIssue.Exploit res = VulnerabilityIssue.Exploit.builder()
                .url(exploit.getUrl())
                .text(exploit.getText())
                .type(exploit.getType())
                .build();
        if (null != exploit.getParameters() && !exploit.getParameters().isEmpty())
            res.setParameter(exploit.getParameters().stream().map(IssuesConverter::convert).collect(Collectors.toList()));
        return res;
    }

    public static VulnerabilityIssue.Exploit.Parameter convert(final V36ExploitParameter parameter) {
        if (null == parameter) return null;
        return VulnerabilityIssue.Exploit.Parameter.builder()
                .name(parameter.getName())
                .value(parameter.getValue())
                .source(parameter.getSource())
                .dependency(parameter.getDependency())
                .payload(parameter.getPayload())
                .vulnerable(parameter.getVulnerable())
                .build();
    }

    public static VulnerabilityIssue.BestPlaceToFix convert(final V36BestPlaceToFix bpf) {
        if (null == bpf) return null;
        return VulnerabilityIssue.BestPlaceToFix.builder()
                .place(convert(bpf.getPlace()))
                .build();
    }

    public static BaseSourceIssue.Place convert(final V36Place place) {
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
    public static ScaIssue.Cvss convert(final V36CvssMetadata cvss) {
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
     * @param description Vulnerability type description from PT AI v.3.6
     */
    protected static void setBaseFields(
            @NonNull final IssueBase source,
            @NonNull final BaseIssue destination,
            @NonNull final DescriptionBaseValue description) {
        destination.setId(source.getId());
        destination.setScanResultId(Objects.requireNonNull(source.getScanResultId()));
        destination.setClazz(ISSUE_TYPE_MAP.get(source.getPropertyClass()));
        destination.setLevel(ISSUE_LEVEL_MAP.get(source.getLevel()));
        destination.setTitle(Objects.requireNonNull(description.getHeader()));

        destination.setApprovalState(ISSUE_APPROVAL_STATE_MAP.get(source.getApprovalState()));
        destination.setFavorite(source.getIsFavorite());
        destination.setSuppressed(source.getIsSuppressed());
        destination.setSuspected(source.getIsSuspected());
        destination.setNewInScanResultId(source.getIsNewInScanResultId());
        destination.setOldInScanResultId(source.getIsOldInScanResultId());
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
            V36CvssMetadata value = on(metadata).call("getCvss").get();
            on(issue).call("setCvss", convert(value));
        }
        if (haveAccessor(metadata, "getLevel") && haveAccessor(issue, "setLevel", IssueLevel.class)) {
            IssueLevel value = on(metadata).call("getLevel").get();
            on(issue).call("setLevel", ISSUE_LEVEL_MAP.get(value));
        }
    }

    /**
     * Method converts PT AI v.3.6 API issue to list of API version independent vulnerabilities
     * @param issueBase Base information about vulnerability. Exact descendant iccue class type dependes
     *                  on a propertyClass field value
     * @param metadataMap Map of all issues metadatas. Used to enrich result issue with OWASP, CWE, NIST etc. IDs
     * @param descriptionsMap Map of all issues descriptions. Used to enrich result issue with title
     * @return PT AI API version independent vulnerability instance
     */
    protected static List<BaseIssue> convert(
            @NonNull final IssueBase issueBase,
            @NonNull final Map<String, IssueBaseMetadata> metadataMap,
            @NonNull final Map<String, IssueDescriptionModel> descriptionsMap) {
        // PT AI API uses string representation for issue class field
        IssueType issueType = IssueType.valueOf(issueBase.getPropertyClass());
        // All issues except SCA ones are linked to metadata and descriptions using type field.
        // SCA uses array of fingerprint IDs and those are to be processed separately
        IssueBaseMetadata baseMetadata = null;
        // The same approach applied to descriptions: type field for all except SCA issues that use array of fingerprint IDs
        DescriptionBaseValue description = null;

        if (IssueType.Fingerprint != issueType) {
            baseMetadata = metadataMap.get(issueBase.getType());
            if (null == baseMetadata) {
                log.warn("Skipping issue " + issueBase.getId() + " as there were no metadata found");
                log.trace(issueBase.toString());
                return null;
            }
            // The same approach applied to descriptions
            IssueDescriptionModel idm = descriptionsMap.get(issueBase.getType());
            if (null == idm || null == idm.getDescriptionValue() || StringUtils.isEmpty(idm.getDescriptionValue().getHeader())) {
                log.warn("Skipping issue " + issueBase.getId() + " as there were no description found");
                log.trace(issueBase.toString());
                return null;
            }
            description = idm.getDescriptionValue();
        }

        if (IssueType.BlackBox == issueType && issueBase instanceof V36BlackBoxIssue) {
                V36BlackBoxIssue issue = (V36BlackBoxIssue) issueBase;

                BlackBoxIssue res = new BlackBoxIssue();
                setBaseFields(issue, res, description);
                applyMetadata(baseMetadata, res);

                return Collections.singletonList(res);
        } else if (IssueType.Configuration == issueType && issueBase instanceof V36ConfigurationIssue) {
            V36ConfigurationIssue issue = (V36ConfigurationIssue) issueBase;

            ConfigurationIssue res = new ConfigurationIssue();
            setBaseFields(issue, res, description);
            applyMetadata(baseMetadata, res);

            res.setVulnerableExpression(convert(issue.getVulnerableExpression()));
            res.setCurrentValue(issue.getExistingValue());
            res.setRecommendedValue(issue.getRecommendedValue());

            return Collections.singletonList(res);
        } else if (IssueType.Fingerprint == issueType) {
            V36FingerprintIssue issue = (V36FingerprintIssue) issueBase;

            List<String> fingerprintIds = issue.getFingerprintIds();
            if (null == fingerprintIds || fingerprintIds.isEmpty()) return null;
            List<BaseIssue> scaIssues = new ArrayList<>();
            for (String fingerprintId : fingerprintIds) {
                baseMetadata = metadataMap.get(fingerprintId);
                if (null == baseMetadata) {
                    log.warn("Skipping issue " + issueBase.getId() + " as there were no metadata found");
                    log.trace(issueBase.toString());
                    continue;
                }
                IssueDescriptionModel idm = descriptionsMap.get(fingerprintId);
                if (null == idm || null == idm.getDescriptionValue() || StringUtils.isEmpty(idm.getDescriptionValue().getHeader())) {
                    log.warn("Skipping issue " + issueBase.getId() + " as there were no description found");
                    log.trace(issueBase.toString());
                    return null;
                }
                description = idm.getDescriptionValue();
                // SCA issues details are located in
                ScaIssue res = new ScaIssue();
                setBaseFields(issue, res, description);
                applyMetadata(baseMetadata, res);
                res.setFingerprintId(fingerprintId);
                res.setComponentName(issue.getComponentName());
                res.setComponentVersion(issue.getComponentVersion());
                if (null != issue.getVulnerableExpression())
                    res.setFile(issue.getVulnerableExpression().getFile());
                // As single file may be subject to a multiple vulnerabilities, we need to
                // create separate issue for each fingerprint and use metadata values
                scaIssues.add(res);
            }
            return scaIssues;
        } else if (IssueType.Unknown == issueType) {
            V36UnknownIssue issue = (V36UnknownIssue) issueBase;

            UnknownIssue res = new UnknownIssue();
            setBaseFields(issue, res, description);
            return Collections.singletonList(res);
        } else if (IssueType.Vulnerability == issueType) {
            V36VulnerabilityIssue issue = (V36VulnerabilityIssue) issueBase;

            VulnerabilityIssue res = new VulnerabilityIssue();
            setBaseFields(issue, res, description);
            applyMetadata(baseMetadata, res);

            res.setSecondOrder(issue.getIsSecondOrder());
            res.setPvf(issue.getFunction());
            res.setVulnerableExpression(convert(issue.getVulnerableExpression()));
            res.setEntryPoint(convert(issue.getEntryPoint()));

            List<V36Place> entries = issue.getTaintDataEntries();
            if (null != entries && !entries.isEmpty())
                res.setTaintDataEntries(entries.stream().map(IssuesConverter::convert).collect(Collectors.toList()));
            entries = issue.getDataTrace();
            if (null != entries && !entries.isEmpty())
                res.setDataTrace(entries.stream().map(IssuesConverter::convert).collect(Collectors.toList()));
            if (!SCAN_MODE_MAP.containsKey(Objects.requireNonNull(issue.getScanMode(), "Issue scan mode is null"))) {
                log.warn("Skipping issue " + issueBase.getId() + " with unknown scan mode " + issue.getScanMode().toString());
                log.trace(issueBase.toString());
                return null;
            }
            res.setScanMode(SCAN_MODE_MAP.get(issue.getScanMode()));
            res.setBpf(convert(issue.getBestPlaceToFix()));
            res.setConditions(issue.getAdditionalConditions());
            res.setExploit(convert(issue.getExploit()));
            res.setAutocheckExploit(convert(issue.getAutocheckExploit()));

            return Collections.singletonList(res);
        } else if (IssueType.Weakness == issueType) {
            V36WeaknessIssue issue = (V36WeaknessIssue) issueBase;

            WeaknessIssue res = new WeaknessIssue();
            setBaseFields(issue, res, description);
            applyMetadata(baseMetadata, res);
            res.setVulnerableExpression(convert(issue.getVulnerableExpression()));

            return Collections.singletonList(res);
        } else if (IssueType.YaraMatch == issueType) {
            V36YaraMatchIssue issue = (V36YaraMatchIssue) issueBase;

            YaraMatchIssue res = new YaraMatchIssue();
            setBaseFields(issue, res, description);
            return Collections.singletonList(res);
        } else
            return null;
    }

    /**
     * Method converts PT AI API version independent language to PT AI v.3.6 API language
     * @param language PT AI API version independent language
     * @return PT AI v.3.6 API language
     */
    @NonNull
    public static V36ProgrammingLanguage convert(@NonNull final ScanResult.ScanSettings.Language language) {
        V36ProgrammingLanguage res = REVERSE_LANGUAGE_MAP.get(language);
        return null == res ? V36ProgrammingLanguage.NONE : res;
    }

    public static final IssuesModel EMPTY_ISSUES_MODEL = new IssuesModel();

    /**
     * Method reads data from stream and deserializes it to PT AI v.3.6 IssuesModel instance
     * @param data Serialized stream of PT AI v.3.6 API data issues list with detailed information about vulnerabilities found
     * @return Deserialized IssuesModel instance
     */
    @SneakyThrows
    protected static IssuesModel parseIssuesModelStream(@NonNull final InputStream data) {
        JSON parser = new JSON();
        MemoryUsage usage = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();
        try {
            log.debug("JVM heap memory use {} / {}", FileCollector.bytesToString(usage.getUsed()), FileCollector.bytesToString(usage.getMax()));
            return parser.getGson().fromJson(new InputStreamReader(data), IssuesModel.class);
        } catch (OutOfMemoryError e) {
            log.error("IssuesModel file parse failed due to lack of heap memory", e);
            return EMPTY_ISSUES_MODEL;
        }
    }

    /**
     * Method converts PT AI v.3.6 API scan result and issues model pair to API version independent scan result
     * @param scanResult PT AI v.3.6 API scan result that contains scan statistic
     * @param model Serialized stream of PT AI v.3.6 API scan issues list with detailed information about vulnerabilities found
     * @param scanSettings PT AI v.3.6 API scan settings
     * @return PT AI API version independent scan results instance
     */
    @SneakyThrows
    public static ScanResult convert(
            @NonNull final com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult scanResult,
            @NonNull final InputStream model,
            @NonNull final V36ScanSettings scanSettings) {
        return convert(scanResult, parseIssuesModelStream(model), scanSettings);
    }

    public static void convertInto(
            @NonNull final com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult scanResult,
            @NonNull final V36ScanSettings scanSettings,
            @NonNull final ScanBrief destination) {
        destination.setPtaiApiVersion(PTAI_API_VERSION);
        destination.setId(Objects.requireNonNull(scanResult.getId(), "Scan result ID is null"));
        destination.setProjectId(Objects.requireNonNull(scanResult.getProjectId(), "Scan result project ID is null"));
        destination.setScanSettings(convert(scanSettings));

        ScanResultStatistic statistic = Objects.requireNonNull(scanResult.getStatistic(), "Scan result statistics is null");
        destination.setStatistic(convert(statistic, scanResult));

        ScanProgress progress = Objects.requireNonNull(scanResult.getProgress(), "Scan result progress is null");
        destination.setState(STATE_MAP.get(progress.getStage()));

        destination.setPolicyState(POLICY_STATE_MAP.get(statistic.getPolicyState()));
    }

    public static ScanBrief convert(
            @NonNull final com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.ScanResult scanResult,
            @NonNull final V36ScanSettings scanSettings) {
        ScanBrief res = new ScanBrief();
        convertInto(scanResult, scanSettings, res);
        return res;
    }
}
