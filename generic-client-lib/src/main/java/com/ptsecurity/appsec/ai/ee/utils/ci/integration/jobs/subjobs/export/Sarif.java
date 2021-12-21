package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export;

import com.contrastsecurity.sarif.*;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ReportsTasks;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;

import java.net.URI;
import java.util.*;

import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.EN;
import static com.ptsecurity.appsec.ai.ee.scan.reports.Reports.Locale.RU;

@Slf4j
@Getter
@Setter
@SuperBuilder
@RequiredArgsConstructor
@ToString
public class Sarif extends Export {
    @NonNull
    protected final Reports.Sarif sarif;

    @Override
    public void validate() throws GenericException {
        ReportsTasks reportsTasks = new Factory().reportsTasks(owner.getClient());
        reportsTasks.check(sarif);
    }

    @Override
    public void execute(@NonNull ScanBrief scanBrief) throws GenericException {
        ReportsTasks reportsTasks = new Factory().reportsTasks(owner.getClient());
        try {
            reportsTasks.exportSarif(scanBrief.getProjectId(), scanBrief.getId(), sarif, owner.getFileOps());
        } catch (GenericException e) {
            owner.warning(e);
        }
    }

    private static final Map<BaseIssue.Level, Result.Level> ISSUE_LEVEL_MAP = new HashMap<>();
    private static final Map<BaseIssue.ApprovalState, Result.Kind> ISSUE_KIND_MAP = new HashMap<>();

    static {
        ISSUE_LEVEL_MAP.put(BaseIssue.Level.NONE, Result.Level.NONE);
        ISSUE_LEVEL_MAP.put(BaseIssue.Level.POTENTIAL, Result.Level.NOTE);
        ISSUE_LEVEL_MAP.put(BaseIssue.Level.LOW, Result.Level.NOTE);
        ISSUE_LEVEL_MAP.put(BaseIssue.Level.MEDIUM, Result.Level.WARNING);
        ISSUE_LEVEL_MAP.put(BaseIssue.Level.HIGH, Result.Level.ERROR);

        ISSUE_KIND_MAP.put(BaseIssue.ApprovalState.APPROVAL, Result.Kind.FAIL);
        ISSUE_KIND_MAP.put(BaseIssue.ApprovalState.AUTO_APPROVAL, Result.Kind.FAIL);
        ISSUE_KIND_MAP.put(BaseIssue.ApprovalState.DISCARD, Result.Kind.PASS);
        ISSUE_KIND_MAP.put(BaseIssue.ApprovalState.NONE, Result.Kind.OPEN);
        ISSUE_KIND_MAP.put(BaseIssue.ApprovalState.NOT_EXIST, Result.Kind.NOT_APPLICABLE);

    }

    @SneakyThrows
    @NonNull
    public static SarifSchema210 convert(@NonNull final ScanResult scanResult, final boolean processGroups) {
        SarifSchema210 sarif = new SarifSchema210()
                .withVersion(SarifSchema210.Version._2_1_0);

        Run sarifRun = new Run().withResults(new ArrayList<>());
        sarif.setRuns(Collections.singletonList(sarifRun));

        Tool sarifTool = new Tool();
        sarifRun.setTool(sarifTool);

        ToolComponent driver = new ToolComponent()
                .withName("Positive Technologies Application Inspector")
                .withInformationUri(new URI("https://www.ptsecurity.com/ww-en/products/ai/"))
                .withOrganization("Positive Technologies")
                .withRules(new HashSet<>());
        sarifTool.setDriver(driver);

        ToolComponent translations = new ToolComponent()
                .withLanguage(RU.getValue())
                .withName(driver.getName())
                .withRules(new HashSet<>());
        sarifRun.setTranslations(Collections.singleton(translations));

        Set<String> ruleIds = new HashSet<>();
        Map<String, Result> resultGroups = new HashMap<>();

        for (BaseIssue issue : scanResult.getIssues()) {
            // Check if issue's title and descriptions are added to rules / translations already
            if (!ruleIds.contains(issue.getTypeId())) {
                for (Reports.Locale locale : Reports.Locale.values()) {
                    com.ptsecurity.appsec.ai.ee.scan.result.ScanResult.Strings title = scanResult.getI18n().get(issue.getTypeId()).get(locale);
                    ReportingDescriptor rule = new ReportingDescriptor()
                            .withId(issue.getTypeId())
                            .withName(title.getTitle())
                            .withProperties(new PropertyBag().withTags(Collections.singleton(issue.getClazz().name().toLowerCase())))
                            .withFullDescription(new MultiformatMessageString().withText(title.getDescription()));
                    if (EN.equals(locale))
                        driver.getRules().add(rule);
                    else
                        translations.getRules().add(rule);
                }
                ruleIds.add(issue.getTypeId());
            }
            // Process issue
            Location location = new Location();
            Set<String> tags = new HashSet<>();
            Result result = new Result()
                    .withRuleId(issue.getTypeId())
                    .withMessage(new Message().withText(scanResult.getI18n().get(issue.getTypeId()).get(EN).getTitle()))
                    .withLevel(ISSUE_LEVEL_MAP.get(issue.getLevel()))
                    .withKind(ISSUE_KIND_MAP.get(issue.getApprovalState()))
                    .withLocations(Collections.singletonList(location))
                    .withProperties(new PropertyBag().withTags(tags));
            tags.add(issue.getClazz().name());
            if (BaseIssue.Type.SCA.equals(issue.getClazz())) {
                ScaIssue scaIssue = (ScaIssue) issue;
                // Set SCA issue location. That location is file-scope only and
                // doesn't contain line and column numbers
                location.withPhysicalLocation(
                        new PhysicalLocation()
                                .withArtifactLocation(
                                        new ArtifactLocation()
                                                .withUri(fixUri(scaIssue.getFile()))
                                                .withUriBaseId("SRCROOT")
                                ));
            } else if (BaseIssue.Type.BLACKBOX.equals(issue.getClazz()))
                // As SARIF is a Static Analysis Results Interchange Format, there's no way to represent DAST results
                continue;
            else if (BaseIssue.Type.CONFIGURATION.equals(issue.getClazz())) {
                ConfigurationIssue configurationIssue = (ConfigurationIssue) issue;
                location.withPhysicalLocation(phl(configurationIssue.getVulnerableExpression()));
            } else if (BaseIssue.Type.UNKNOWN.equals(issue.getClazz()))
                continue;
            else if (BaseIssue.Type.VULNERABILITY.equals(issue.getClazz())) {
                VulnerabilityIssue vulnerabilityIssue = (VulnerabilityIssue) issue;
                location.withPhysicalLocation(phl(vulnerabilityIssue.getVulnerableExpression()));
                // Need special processing for groupId as those vulnerabilities are to be
                // represented by same result with multiple codeFlows
                boolean existingResult = StringUtils.isNotEmpty(issue.getGroupId()) && resultGroups.containsKey(issue.getGroupId());
                // Some of SARIF viewers like VS.Code plugin lack ability to show multiple flows for
                // single vulnerability. If processGroups equals to false then no grouping will be done
                // and every vulnerability will be represented as a standalone separate result
                if (!processGroups) existingResult = false;
                if (existingResult) result = resultGroups.get(issue.getGroupId());
                if (!existingResult) {
                    resultGroups.put(issue.getGroupId(), result);
                    sarifRun.getResults().add(result);
                }

                List<ThreadFlowLocation> threadFlowLocations = new ArrayList<>();
                addTfl(threadFlowLocations, vulnerabilityIssue.getEntryPoint(), "Entry point");
                addTfl(threadFlowLocations, vulnerabilityIssue.getTaintDataEntries(), "Taint data entry");
                addTfl(threadFlowLocations, vulnerabilityIssue.getDataTrace(), "Data operation");
                addTfl(threadFlowLocations, vulnerabilityIssue.getVulnerableExpression(), "Exit point");

                if (!threadFlowLocations.isEmpty()) {
                    if (null == result.getCodeFlows()) result.setCodeFlows(new ArrayList<>());
                    List<CodeFlow> codeFlows = result.getCodeFlows();
                    codeFlows.add(new CodeFlow().withThreadFlows(Collections.singletonList(new ThreadFlow().withLocations(threadFlowLocations))));
                }
                continue;
            } else if (BaseIssue.Type.WEAKNESS.equals(issue.getClazz())) {
                WeaknessIssue weaknessIssue = (WeaknessIssue) issue;
                location.withPhysicalLocation(phl(weaknessIssue.getVulnerableExpression()));
            } else if (BaseIssue.Type.YARAMATCH.equals(issue.getClazz()))
                continue;

            sarifRun.getResults().add(result);
        }
        return sarif;
    }

    public static String fixUri(@NonNull final String uri) {
        return StringUtils.removeStart(uri, ".\\").replaceAll("\\\\", "/");
    }

    public static PhysicalLocation phl(@NonNull final BaseSourceIssue.Place place) {
        Region region = new Region().withSnippet(new ArtifactContent().withText(place.getValue()));
        if (place.getBeginLine() > 0) region.setStartLine(place.getBeginLine());
        if (place.getEndLine() > 0) region.setEndLine(place.getEndLine());
        if (place.getBeginColumn() > 0) region.setStartColumn(place.getBeginColumn());
        if (place.getEndColumn() > 0) region.setEndColumn(place.getEndColumn());

        return new PhysicalLocation()
                .withArtifactLocation(new ArtifactLocation()
                        .withUri(fixUri(place.getFile()))
                        .withUriBaseId("SRCROOT"))
                .withRegion(region);
    }

    public static ThreadFlowLocation tfl(@NonNull final BaseSourceIssue.Place place, final String text) {
        return new ThreadFlowLocation()
                .withLocation(
                        new Location()
                                .withMessage(new Message().withText(text))
                                .withPhysicalLocation(phl(place)));
    }

    public static void addTfl(List<ThreadFlowLocation> list, final BaseSourceIssue.Place place, final String text) {
        if (null != place) list.add(tfl(place, text));
    }

    public static void addTfl(List<ThreadFlowLocation> list, final List<BaseSourceIssue.Place> placeList, final String text) {
        if (CollectionUtils.isEmpty(placeList)) return;
        for (BaseSourceIssue.Place place : placeList)
            if (null != place) list.add(tfl(place, text));
    }
}
