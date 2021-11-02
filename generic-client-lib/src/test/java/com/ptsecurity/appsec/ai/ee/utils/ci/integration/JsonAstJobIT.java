package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.*;
import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.RawJson;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state.FailIfAstFailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.JsonAstJobSetupOperationsImpl;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsHelper;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.experimental.SuperBuilder;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.UUID;
import java.util.function.Consumer;

import static com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue.Level.*;

@DisplayName("Test JSON-based AST")
@Tag("integration")
public class JsonAstJobIT extends BaseAstIT {
    @SuperBuilder
    public static class JsonAstJobImpl extends UiAstJobIT.UiAstJobImpl {
        protected String jsonSettings;

        protected String jsonPolicy;

        @Override
        protected void init() throws GenericException {
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
    @Test
    @DisplayName("Scan PHP smoke project with medium level vulnerabilities using JSON settings and policy")
    public void scanPhpSmoke() {
        Path sources = getSourcesRoot(PHP_SMOKE_MEDIUM);
        Path destination = Files.createTempDirectory(TEMP_FOLDER, "ptai-");

        String jsonSettings = getResourceString("json/scan/settings/settings.minimal.aiproj");
        Assertions.assertFalse(StringUtils.isEmpty(jsonSettings));

        AiProjScanSettings settings = JsonSettingsHelper.verify(jsonSettings);
        settings.setProjectName("junit-" + UUID.randomUUID());
        settings.setProgrammingLanguage(ScanBrief.ScanSettings.Language.PHP);
        settings.setScanAppType("PHP");
        settings.setIsUseEntryAnalysisPoint(true);
        settings.setIsUsePublicAnalysisMethod(true);
        jsonSettings = JsonSettingsHelper.serialize(settings);

        GenericAstJob astJob = JsonAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .connectionSettings(CONNECTION_SETTINGS)
                .console(System.out)
                .sources(sources)
                .destination(destination)
                .jsonSettings(jsonSettings)
                .build();

        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);
    }

    @SneakyThrows
    public ScanResult analyseMiscScanResults(@NonNull final Consumer<AiProjScanSettings> modifySettings) {
        Path sources = getSourcesRoot(PHP_SMOKE_MISC);
        Path destination = Files.createTempDirectory(TEMP_FOLDER, "ptai-");

        String jsonSettings = getResourceString("json/scan/settings/settings.minimal.aiproj");
        Assertions.assertFalse(StringUtils.isEmpty(jsonSettings));

        AiProjScanSettings settings = JsonSettingsHelper.verify(jsonSettings);
        settings.setProjectName("junit-" + UUID.randomUUID());
        settings.setProgrammingLanguage(ScanBrief.ScanSettings.Language.PHP);
        modifySettings.accept(settings);
        jsonSettings = JsonSettingsHelper.serialize(settings);

        GenericAstJob astJob = JsonAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .connectionSettings(CONNECTION_SETTINGS)
                .console(System.out)
                .sources(sources)
                .destination(destination)
                .jsonSettings(jsonSettings)
                .build();
        RawJson.builder().owner(astJob).rawData(rawData).build().attach(astJob);
        FailIfAstFailed.builder().build().attach(astJob);

        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);

        File json = destination.resolve(rawData.getFileName()).toFile();
        Assertions.assertTrue(json.exists());
        return BaseJsonHelper.createObjectMapper().readValue(json, ScanResult.class);
    }

    @SneakyThrows
    @Test
    @DisplayName("Check PHP smoke miscellaneous project scan results contain low level vulnerabilities only")
    public void checkLowLevelVulnerabilitiesOnly() {
        ScanResult scanResult = analyseMiscScanResults((settings) -> {
            settings.setScanAppType("Configuration");
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

    @SneakyThrows
    @Test
    @DisplayName("Check PHP smoke miscellaneous project scan results contain SCA high, medium, low and none level vulnerabilities")
    public void checkScaVulnerabilitiesOnly() {
        ScanResult scanResult = analyseMiscScanResults((settings) -> {
            settings.setScanAppType("Fingerprint");
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

    @SneakyThrows
    @Test
    @DisplayName("Check PHP smoke miscellaneous project scan results contain PM potential level vulnerabilities only")
    public void checkPmVulnerabilitiesOnly() {
        ScanResult scanResult = analyseMiscScanResults((settings) -> {
            settings.setScanAppType("PmTaint");
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

    @SneakyThrows
    @Test
    @DisplayName("Check PHP smoke miscellaneous project scan results contain public / protected vulnerabilities only")
    public void checkPublicProtectedVulnerabilitiesOnly() {
        ScanResult scanResult = analyseMiscScanResults((settings) -> {
            settings.setScanAppType("PHP");
            settings.setUseTaintAnalysis(false);
            settings.setUsePmAnalysis(true);
            settings.setIsUseEntryAnalysisPoint(false);
            settings.setIsUsePublicAnalysisMethod(true);
        });
        Assertions.assertNotNull(scanResult);
        Assertions.assertNotEquals(0, scanResult.getIssues().size());
        long publicProtectedCount = scanResult.getIssues().stream()
                .filter(i -> i instanceof VulnerabilityIssue)
                .map(i -> (VulnerabilityIssue) i)
                .filter(c -> VulnerabilityIssue.ScanMode.FROM_PUBLICPROTECTED == c.getScanMode()).count();
        Assertions.assertEquals(scanResult.getIssues().size(), publicProtectedCount);
    }

    @SneakyThrows
    @Test
    @DisplayName("Check PHP smoke miscellaneous project scan results contain different vulnerabilities")
    public void checkAllVulnerabilities() {
        ScanResult scanResult = analyseMiscScanResults((settings) -> {
            settings.setScanAppType("PHP, PmTaint, Configuration, Fingerprint");
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

    @SneakyThrows
    @Test
    @DisplayName("Check PHP smoke miscellaneous project scan settings change")
    public void checkScanSettingsChange() {
        ScanResult firstScanResult = analyseMiscScanResults((settings) -> {
            settings.setScanAppType("PHP, PmTaint, Configuration, Fingerprint");
            settings.setUseTaintAnalysis(true);
            settings.setUsePmAnalysis(true);
            settings.setIsUseEntryAnalysisPoint(true);
            settings.setIsUsePublicAnalysisMethod(true);
            settings.setCustomParameters("-l php");
        });
        Assertions.assertNotNull(firstScanResult);
        // As analyseMiscScanResults generates random project name, let's store it
        String projectName = firstScanResult.getProjectName();
        ScanResult secondScanResult = analyseMiscScanResults((settings) -> {
            settings.setScanAppType("PHP");
            settings.setIsUseEntryAnalysisPoint(true);
            settings.setIsUsePublicAnalysisMethod(false);
            settings.setProjectName(projectName);
        });
        Assertions.assertNotNull(secondScanResult);
        Assertions.assertTrue(firstScanResult.getIssues().size() > secondScanResult.getIssues().size());
    }
}
