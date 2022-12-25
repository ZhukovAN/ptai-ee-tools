package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.*;
import com.ptsecurity.appsec.ai.ee.scan.settings.AbstractAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.RawJson;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state.FailIfAstFailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.JsonAstJobSetupOperationsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsTestHelper;
import com.ptsecurity.misc.tools.TempFile;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;

import java.io.File;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ApiVersion.V411;
import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ApiVersion.V420;
import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.PHP;
import static com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue.Level.*;
import static com.ptsecurity.appsec.ai.ee.scan.settings.AbstractAiProjScanSettings.ScanAppType.*;
import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.Project.*;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;
import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;

@DisplayName("Test JSON-based AST")
@Tag("integration")
@Slf4j
public class JsonAstJobIT extends BaseAstIT {
    @SuperBuilder
    public static class JsonAstJobImpl extends UiAstJobIT.UiAstJobImpl {
        protected String jsonSettings;

        protected String jsonPolicy;

        @Override
        public void init() throws GenericException {
            astOps = TestAstOperations.builder()
                    .owner(this)
                    .sources(sources)
                    .build();
            fileOps = TestFileOperations.builder()
                    .owner(this)
                    .destination(destination)
                    .build();
            setupOps = JsonAstJobSetupOperationsImpl.builder()
                    .owner(this)
                    .jsonPolicy(jsonPolicy)
                    .jsonSettings(jsonSettings)
                    .build();
        }
    }

    @SneakyThrows
    protected void scanProjectTwice(@NonNull final Project project) {
        try (TempFile destination = TempFile.createFolder()) {
            GenericAstJob astJob = JsonAstJobImpl.builder()
                    .async(false)
                    .fullScanMode(true)
                    .connectionSettings(CONNECTION_SETTINGS())
                    .console(System.out)
                    .sources(project.getCode())
                    .destination(destination.toPath())
                    .jsonSettings(new JsonSettingsTestHelper(project.getSettings())
                            .isUseEntryAnalysisPoint(true)
                            .isUsePublicAnalysisMethod(true)
                            .projectName("junit-" + UUID.randomUUID())
                            .serialize())
                    .jsonPolicy(getResourceString("json/scan/settings/policy.generic.json"))
                    .build();

            for (int i = 0 ; i < 2 ; i++) {
                AbstractJob.JobExecutionResult res = astJob.execute();
                Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);
            }
        }
    }

    @SneakyThrows
    public ScanResult scanPhpSmokeMisc(@NonNull final Consumer<JsonSettingsTestHelper> modifySettings) {
        try (TempFile destination = TempFile.createFolder()) {

            JsonSettingsTestHelper settings = new JsonSettingsTestHelper(PHP_SMOKE.getSettings());
            settings.setProgrammingLanguage(PHP);
            modifySettings.accept(settings);

            GenericAstJob astJob = JsonAstJobImpl.builder()
                    .async(false)
                    .fullScanMode(true)
                    .connectionSettings(CONNECTION_SETTINGS())
                    .console(System.out)
                    .sources(PHP_SMOKE.getCode())
                    .destination(destination.toPath())
                    .jsonSettings(settings.serialize())
                    .build();
            RawJson.builder().owner(astJob).rawData(rawData).build().attach(astJob);
            FailIfAstFailed.builder().build().attach(astJob);

            AbstractJob.JobExecutionResult res = astJob.execute();
            Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);

            File json = destination.toPath().resolve(rawData.getFileName()).toFile();
            Assertions.assertTrue(json.exists());
            return createObjectMapper().readValue(json, ScanResult.class);
        }
    }

    @Test
    @Tag("scan")
    @DisplayName("Check PHP smoke miscellaneous project scan results contain low level vulnerabilities only")
    public void checkLowLevelVulnerabilitiesOnly(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        ScanResult scanResult = scanPhpSmokeMisc((settings) -> {
            settings.setScanAppType(CONFIGURATION);
            settings.setIsUseEntryAnalysisPoint(true);
        });
        Assertions.assertNotNull(scanResult);
        Assertions.assertNotEquals(0, scanResult.getIssues().size());
        long lowLevelCount = scanResult.getIssues().stream()
                .filter(i -> i instanceof ConfigurationIssue)
                .map(i -> (ConfigurationIssue) i)
                .filter(c -> LOW == c.getLevel()).count();
        Assertions.assertEquals(scanResult.getIssues().size(), lowLevelCount);
    }

    @Test
    @Tag("scan")
    @DisplayName("Check PHP smoke miscellaneous project scan results contain SCA high, medium, low and none level vulnerabilities")
    public void checkScaVulnerabilitiesOnly(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        ScanResult scanResult = scanPhpSmokeMisc((settings) -> {
            settings.setScanAppType(FINGERPRINT);
            settings.setIsUseEntryAnalysisPoint(true);
        });
        Assertions.assertNotNull(scanResult);
        Assertions.assertNotEquals(0, scanResult.getIssues().size());
        long count = scanResult.getIssues().stream()
                .filter(i -> i instanceof ScaIssue)
                .map(i -> (ScaIssue) i)
                .filter(c -> HIGH == c.getLevel() || MEDIUM == c.getLevel() || LOW == c.getLevel() || NONE == c.getLevel())
                .count();
        Assertions.assertEquals(scanResult.getIssues().size(), count);
    }

    @Test
    @Tag("scan")
    @DisplayName("Check PHP smoke miscellaneous project scan results contain PM potential level vulnerabilities only")
    public void checkPmVulnerabilitiesOnly(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        ScanResult scanResult = scanPhpSmokeMisc((settings) -> {
            settings.setScanAppType(PMTAINT);
            settings.setUseTaintAnalysis(false);
            settings.setUsePmAnalysis(true);
            settings.setIsUseEntryAnalysisPoint(true);
        });
        Assertions.assertNotNull(scanResult);
        Assertions.assertNotEquals(0, scanResult.getIssues().size());
        long potentialLevelCount = scanResult.getIssues().stream()
                .filter(i -> i instanceof WeaknessIssue)
                .map(i -> (WeaknessIssue) i)
                .filter(c -> BaseIssue.Level.POTENTIAL == c.getLevel()).count();
        Assertions.assertEquals(scanResult.getIssues().size(), potentialLevelCount);
    }

    @Test
    @Tag("scan")
    @DisplayName("Check PHP smoke miscellaneous project scan results contain public / protected vulnerabilities only")
    public void checkPublicProtectedVulnerabilitiesOnly(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        ScanResult scanResult = scanPhpSmokeMisc((settings) -> {
            settings.setScanAppType(AbstractAiProjScanSettings.ScanAppType.PHP);
            settings.setUseTaintAnalysis(false);
            settings.setUsePmAnalysis(true);
            settings.setIsUseEntryAnalysisPoint(false);
            settings.setIsUsePublicAnalysisMethod(true);
        });
        Assertions.assertNotNull(scanResult);
        Assertions.assertNotEquals(0, scanResult.getIssues().size());
        // There's no way to disable entry point analysis in 4.0+ so results will always contain these issues
        long publicProtectedCount = scanResult.getIssues().stream()
                .filter(i -> i instanceof VulnerabilityIssue)
                .map(i -> (VulnerabilityIssue) i)
                .filter(c -> VulnerabilityIssue.ScanMode.FROM_PUBLICPROTECTED == c.getScanMode()).count();
        Assertions.assertNotEquals(0, publicProtectedCount);
    }

    @Test
    @Tag("scan")
    @DisplayName("Check PHP smoke miscellaneous project scan results contain different vulnerabilities")
    public void checkAllVulnerabilities(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        ScanResult scanResult = scanPhpSmokeMisc((settings) -> {
            settings.setScanAppType(AbstractAiProjScanSettings.ScanAppType.PHP, PMTAINT, CONFIGURATION, FINGERPRINT);
            settings.setUseTaintAnalysis(false);
            settings.setUsePmAnalysis(true);
            settings.setIsUseEntryAnalysisPoint(true);
            settings.setIsUsePublicAnalysisMethod(true);
        });
        Assertions.assertNotNull(scanResult);
        Assertions.assertNotEquals(0, scanResult.getIssues().size());
        Assertions.assertNotEquals(0, scanResult.getIssues().stream()
                .filter(i -> HIGH == i.getLevel())
                .count());
        Assertions.assertNotEquals(0, scanResult.getIssues().stream()
                .filter(i -> MEDIUM == i.getLevel())
                .count());
        Assertions.assertNotEquals(0, scanResult.getIssues().stream()
                .filter(i -> LOW == i.getLevel())
                .count());
        Assertions.assertNotEquals(0, scanResult.getIssues().stream()
                .filter(i -> BaseIssue.Level.POTENTIAL == i.getLevel())
                .count());
        Assertions.assertNotEquals(0, scanResult.getIssues().stream()
                .filter(i -> HIGH == i.getLevel() || MEDIUM == i.getLevel())
                .filter(i -> i instanceof VulnerabilityIssue)
                .count());
        Assertions.assertNotEquals(0, scanResult.getIssues().stream()
                .filter(i -> HIGH == i.getLevel())
                .filter(i -> i instanceof ScaIssue)
                .count());
        log.trace("Skip CVE sheck as 4.1.1 and 4.2 doesn't provide that info");
        if (V411 != CONNECTION().getVersion() && V420 != CONNECTION().getVersion())
            Assertions.assertNotEquals(0, scanResult.getIssues().stream()
                    .filter(i -> HIGH == i.getLevel())
                    .filter(i -> i instanceof ScaIssue)
                    .filter(s -> ((ScaIssue) s).getCveId().contains("CVE-2016-10033"))
                    .count());
        Assertions.assertNotEquals(0, scanResult.getIssues().stream()
                .filter(i -> i instanceof VulnerabilityIssue)
                .map(i -> (VulnerabilityIssue) i)
                .filter(c -> VulnerabilityIssue.ScanMode.FROM_PUBLICPROTECTED == c.getScanMode())
                .count());
        Assertions.assertNotEquals(0, scanResult.getIssues().stream()
                .filter(i -> i instanceof VulnerabilityIssue)
                .map(i -> (VulnerabilityIssue) i)
                .filter(VulnerabilityIssue::getSecondOrder)
                .count());
    }

    @Test
    @Tag("scan")
    @DisplayName("Check PHP smoke miscellaneous project scan settings change")
    public void checkScanSettingsChange(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        ScanResult firstScanResult = scanPhpSmokeMisc((settings) -> {
            settings.setScanAppType(AbstractAiProjScanSettings.ScanAppType.PHP, PMTAINT, CONFIGURATION, FINGERPRINT);
            settings.setUseTaintAnalysis(true);
            settings.setUsePmAnalysis(true);
            settings.setIsUseEntryAnalysisPoint(true);
            settings.setIsUsePublicAnalysisMethod(true);
            settings.setCustomParameters("-l php");
        });
        Assertions.assertNotNull(firstScanResult);
        // As analyseMiscScanResults generates random project name, let's store it
        String projectName = firstScanResult.getProjectName();
        ScanResult secondScanResult = scanPhpSmokeMisc((settings) -> {
            settings.setScanAppType(AbstractAiProjScanSettings.ScanAppType.PHP);
            settings.setIsUseEntryAnalysisPoint(true);
            settings.setIsUsePublicAnalysisMethod(false);
            settings.setProjectName(projectName);
        });
        Assertions.assertNotNull(secondScanResult);
        Assertions.assertTrue(firstScanResult.getIssues().size() > secondScanResult.getIssues().size());
    }

    @SneakyThrows
    @Test
    @Tag("scan")
    @DisplayName("Check raw report multiflow XSS representation via group Id")
    public void checkMultiflow(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        try (TempFile destination = TempFile.createFolder()) {
            GenericAstJob astJob = JsonAstJobImpl.builder()
                    .async(false)
                    .fullScanMode(true)
                    .connectionSettings(CONNECTION_SETTINGS())
                    .console(System.out)
                    .sources(PHP_SMOKE.getCode())
                    .destination(destination.toPath())
                    .jsonSettings(PHP_SMOKE.getSettings())
                    .build();
            RawJson.builder().owner(astJob).rawData(rawData).build().attach(astJob);

            AbstractJob.JobExecutionResult res = astJob.execute();
            Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);

            Path rawPath = destination.toPath().resolve(rawData.getFileName());
            ScanResult scanResult = createObjectMapper().readValue(rawPath.toFile(), ScanResult.class);
            Map<Optional<String>, Long> groups = scanResult.getIssues().stream()
                    .collect(Collectors.groupingBy(issue -> Optional.ofNullable(issue.getGroupId()), Collectors.counting()));
            log.trace("Skip issues group test as 4.1.1 doesn't provide group Id data");
            if (V411 != CONNECTION().getVersion())
                Assertions.assertTrue(groups.values().stream().anyMatch(l -> l > 1));
        }
    }

    @Test
    @Tag("scan")
    @DisplayName("Scan every (except OWASP Benchmark) project twice: first time as a new project, second time as existing")
    public void scanEveryProjectTwice(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        for (Project project : ALL) {
            if (JAVA_OWASP_BENCHMARK == project) continue;
            scanProjectTwice(project);
        }
    }

    @SneakyThrows
    @Test
    @Tag("scan")
    @DisplayName("Scan project with slash in its name twice using same JSON settings")
    public void scanProjectWithBadCharacter(@NonNull final TestInfo testInfo) {
        log.trace(testInfo.getDisplayName());
        try (TempFile destination = TempFile.createFolder()) {
            JsonSettingsTestHelper settings = new JsonSettingsTestHelper(getResourceString("json/scan/settings/settings.java-app01.aiproj"));
            settings.setProjectName("junit-" + UUID.randomUUID() + "-origin/master");
            for (int i = 0 ; i < 2 ; i++) {
                GenericAstJob astJob = JsonAstJobImpl.builder()
                        .async(false)
                        .fullScanMode(true)
                        .connectionSettings(CONNECTION_SETTINGS())
                        .console(System.out)
                        .sources(JAVA_APP01.getCode())
                        .destination(destination.toPath())
                        .jsonSettings(settings.serialize())
                        .jsonPolicy(getResourceString("json/scan/settings/policy.generic.json"))
                        .build();
                AbstractJob.JobExecutionResult res = astJob.execute();
                Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);
            }
        }
    }
}
