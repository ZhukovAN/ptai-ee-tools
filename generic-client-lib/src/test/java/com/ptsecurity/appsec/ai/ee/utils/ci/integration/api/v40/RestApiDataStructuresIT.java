package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v40;

import com.google.gson.reflect.TypeToken;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.RawData;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.settings.AbstractAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.server.v40.projectmanagement.ApiResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.JsonAstJobIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v40.ApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseClientIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.RawJson;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state.FailIfAstFailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.BaseTest;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.test.utils.TempFile;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.BaseJsonHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsTestHelper;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import okhttp3.Call;
import okhttp3.Request;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.UUID;
import java.util.function.Consumer;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.JAVA;
import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ScanSettings.Language.PHP;
import static com.ptsecurity.appsec.ai.ee.scan.settings.AbstractAiProjScanSettings.ScanAppType.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseAstIT.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@Slf4j
@DisplayName("Test PT AI 4.0 REST API data structures")
@Tag("integration")
public class RestApiDataStructuresIT extends BaseClientIT {

    @SneakyThrows
    protected void generateData(@NonNull final Path destination, @NonNull final BaseAstIT.Project project, @NonNull final Consumer<JsonSettingsTestHelper> modifySettings) {
        if (Connection.Version.V40 != CONNECTION().getVersion()) return;

        RawData rawData = RawData.builder()
                .fileName(UUID.randomUUID() + ".json")
                .build();

        JsonSettingsTestHelper helper = new JsonSettingsTestHelper(project.getSettings());
        helper.setProjectName(project.getName());

        modifySettings.accept(helper);

        GenericAstJob astJob = JsonAstJobIT.JsonAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .connectionSettings(CONNECTION_SETTINGS())
                .console(System.out)
                .sources(project.getCode())
                .destination(destination)
                .jsonSettings(helper.serialize())
                .build();
        RawJson.builder().owner(astJob).rawData(rawData).build().attach(astJob);
        FailIfAstFailed.builder().build().attach(astJob);
        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);

        File json = destination.resolve(rawData.getFileName()).toFile();
        Assertions.assertTrue(json.exists());
        ScanResult scanResult = BaseJsonHelper.createObjectMapper().readValue(json, ScanResult.class);

        ConnectionSettings connectionSettings = CONNECTION_SETTINGS().validate();
        com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v40.ApiClient client = new ApiClient(connectionSettings);
        // Initialize all API clients with URL, timeouts, SSL settings etc.
        client.init();
        client.authenticate();

        Path jsons = destination.resolve("v40").resolve("json");
        jsons.toFile().mkdirs();
        Path scanSettingsDir = jsons.resolve("scanSettings");
        scanSettingsDir.toFile().mkdirs();
        Path scanResultDir = jsons.resolve("scanResult");
        scanSettingsDir.toFile().mkdirs();
        Path issuesModelDir = jsons.resolve("issuesModel");
        issuesModelDir.toFile().mkdirs();

        Call call = client.getLegacyProjectsApi().apiProjectsProjectIdScanSettingsScanSettingsIdGetCall(scanResult.getProjectId(), scanResult.getScanSettings().getId(), null);
        final Type stringType = new TypeToken<String>() {}.getType();
        ApiResponse<String> scanSettingsResponse = client.getProjectsApi().getApiClient().execute(call, stringType);
        FileUtils.writeStringToFile(scanSettingsDir.resolve(project.getName() + ".json").toFile(), scanSettingsResponse.getData(), StandardCharsets.UTF_8);

        call = client.getLegacyProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGetCall(scanResult.getProjectId(), scanResult.getId(), null);
        ApiResponse<String> scanResultResponse = client.getProjectsApi().getApiClient().execute(call, stringType);
        FileUtils.writeStringToFile(scanResultDir.resolve(project.getName() + ".json").toFile(), scanResultResponse.getData(), StandardCharsets.UTF_8);

        for (Reports.Locale locale : Reports.Locale.values()) {
            log.trace("Getting issues data using {} locale", locale);
            File issuesModelFile = client.getLegacyProjectsApi().apiProjectsProjectIdScanResultsScanResultIdIssuesGet(scanResult.getProjectId(), scanResult.getId(), locale.getCode());
            log.debug("Localized ({}) issues stored to temp file {}", locale, issuesModelFile.getAbsolutePath());
            Path sevenZip = issuesModelDir.resolve(project.getName() + "." + locale.getLocale().getLanguage() + ".json.7z");
            sevenZipData(sevenZip, FileUtils.readFileToByteArray(issuesModelFile));
        }
    }

    @SneakyThrows
    @Test
    public void generateRestApiDataStructures() {
        try (TempFile destination = TempFile.createFolder()) {
            generateData(destination.toPath(), JAVA_APP01, (helper) -> {
                helper.setScanAppType(AbstractAiProjScanSettings.ScanAppType.JAVA, CONFIGURATION, FINGERPRINT, PMTAINT);
                helper.isUseEntryAnalysisPoint(true);
                helper.isUsePublicAnalysisMethod(true);
                helper.setIsDownloadDependencies(true);
            });

            generateData(destination.toPath(), JAVA_OWASP_BENCHMARK, (helper) -> {
                helper.setScanAppType(AbstractAiProjScanSettings.ScanAppType.JAVA, PMTAINT);
                helper.isUseEntryAnalysisPoint(false);
                helper.isUsePublicAnalysisMethod(true);
                helper.setUsePmAnalysis(true);
                helper.setUseTaintAnalysis(false);
                helper.setIsDownloadDependencies(true);
            });

            generateData(destination.toPath(), PHP_OWASP_BRICKS, (helper) -> {
                helper.setScanAppType(AbstractAiProjScanSettings.ScanAppType.PHP, CONFIGURATION, FINGERPRINT, PMTAINT);
                helper.isUseEntryAnalysisPoint(true);
                helper.isUsePublicAnalysisMethod(true);
                helper.setUsePmAnalysis(true);
                helper.setUseTaintAnalysis(true);
                helper.setIsDownloadDependencies(false);
            });

            generateData(destination.toPath(), PHP_SMOKE_MULTIFLOW, (helper) -> {
                helper.setScanAppType(AbstractAiProjScanSettings.ScanAppType.PHP);
                helper.isUseEntryAnalysisPoint(true);
                helper.isUsePublicAnalysisMethod(false);
            });

            generateData(destination.toPath(), PHP_SMOKE_HIGH, (helper) -> {
                helper.setScanAppType(AbstractAiProjScanSettings.ScanAppType.PHP);
                helper.isUseEntryAnalysisPoint(true);
                helper.isUsePublicAnalysisMethod(false);
            });

            generateData(destination.toPath(), PHP_SMOKE_MEDIUM, (helper) -> {
                helper.setScanAppType(AbstractAiProjScanSettings.ScanAppType.PHP);
                helper.isUseEntryAnalysisPoint(true);
                helper.isUsePublicAnalysisMethod(false);
            });

            generateData(destination.toPath(), PHP_SMOKE_MISC, (helper) -> {
                helper.setScanAppType(AbstractAiProjScanSettings.ScanAppType.PHP, CONFIGURATION, FINGERPRINT, PMTAINT);
                helper.isUseEntryAnalysisPoint(true);
                helper.isUsePublicAnalysisMethod(true);
                helper.setUsePmAnalysis(true);
                helper.setUseTaintAnalysis(true);
                helper.setIsDownloadDependencies(true);
            });

            log.trace("REST API data generation complete");
        }
    }
}
