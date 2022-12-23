package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v420;

import com.google.gson.reflect.TypeToken;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.RawData;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ApiVersion;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.settings.AbstractAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.server.v420.api.ApiResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.JsonAstJobIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Project;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseClientIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.RawJson;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state.FailIfAstFailed;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json.JsonSettingsTestHelper;
import com.ptsecurity.misc.tools.TempFile;
import com.ptsecurity.misc.tools.helpers.ArchiveHelper;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import okhttp3.Call;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.UUID;
import java.util.function.Consumer;

import static com.ptsecurity.appsec.ai.ee.scan.settings.AbstractAiProjScanSettings.ScanAppType.*;
import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.Project.*;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;

@Slf4j
@DisplayName("Test PT AI 4.2 REST API data structures")
@Tag("development")
public class RestApiDataStructuresIT extends BaseClientIT {

    @SneakyThrows
    protected void generateData(@NonNull final Path destination, @NonNull final Project project, @NonNull final Consumer<JsonSettingsTestHelper> modifySettings) {
        if (ApiVersion.V420 != CONNECTION().getVersion()) return;

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
                // As we directly pass scan settings there's no need to call Project's setup method
                .jsonSettings(helper.serialize())
                .build();
        RawJson.builder().owner(astJob).rawData(rawData).build().attach(astJob);
        FailIfAstFailed.builder().build().attach(astJob);
        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);

        File json = destination.resolve(rawData.getFileName()).toFile();
        Assertions.assertTrue(json.exists());
        ScanResult scanResult = createObjectMapper().readValue(json, ScanResult.class);

        ConnectionSettings connectionSettings = CONNECTION_SETTINGS().validate();
        ApiClient client = new ApiClient(connectionSettings);
        // Initialize all API clients with URL, timeouts, SSL settings etc.
        client.init();
        client.authenticate();

        Path jsons = destination.resolve("v42").resolve("json");
        jsons.toFile().mkdirs();
        Path scanSettingsDir = jsons.resolve("scanSettings");
        scanSettingsDir.toFile().mkdirs();
        Path scanResultDir = jsons.resolve("scanResult");
        scanSettingsDir.toFile().mkdirs();
        Path issuesModelDir = jsons.resolve("issuesModel");
        issuesModelDir.toFile().mkdirs();

        Call call = client.getProjectsApi().apiProjectsProjectIdScanSettingsScanSettingsIdGetCall(scanResult.getProjectId(), scanResult.getScanSettings().getId(), null);
        final Type stringType = new TypeToken<String>() {}.getType();
        ApiResponse<String> scanSettingsResponse = client.getProjectsApi().getApiClient().execute(call, stringType);
        FileUtils.writeStringToFile(scanSettingsDir.resolve(project.getName() + ".json").toFile(), scanSettingsResponse.getData(), StandardCharsets.UTF_8);

        call = client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGetCall(scanResult.getProjectId(), scanResult.getId(), null);
        ApiResponse<String> scanResultResponse = client.getProjectsApi().getApiClient().execute(call, stringType);
        FileUtils.writeStringToFile(scanResultDir.resolve(project.getName() + ".json").toFile(), scanResultResponse.getData(), StandardCharsets.UTF_8);

        call = client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdIssuesGetCall(scanResult.getProjectId(), scanResult.getId(), null);
        ApiResponse<String> scanIssuesResponse = client.getProjectsApi().getApiClient().execute(call, stringType);
        FileUtils.writeStringToFile(issuesModelDir.resolve(project.getName() + ".json").toFile(), scanIssuesResponse.getData(), StandardCharsets.UTF_8);

        for (Reports.Locale locale : Reports.Locale.values()) {
            log.trace("Getting issues data using {} locale", locale);
            call = client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdIssuesHeadersGetCall(scanResult.getProjectId(), scanResult.getId(), locale.getValue(), null);
            ApiResponse<String> scanIssuesHeadersResponse = client.getProjectsApi().getApiClient().execute(call, stringType);
            try (TempFile tempFile = TempFile.createFile()) {
                FileUtils.writeStringToFile(tempFile.toFile(), scanIssuesHeadersResponse.getData(), StandardCharsets.UTF_8);
                log.debug("Localized ({}) issue headers stored to temp file {}", locale, tempFile.toFile().getAbsolutePath());
                Path sevenZip = issuesModelDir.resolve(project.getName() + "." + locale.getLocale().getLanguage() + ".json.7z");
                ArchiveHelper.packData7Zip(sevenZip, FileUtils.readFileToByteArray(tempFile.toFile()));
            };
        }
    }

    @SneakyThrows
    @Test
    public void generateRestApiDataStructures() {
        try (TempFile destination = TempFile.createFolder()) {
            generateData(destination.toPath(), PYTHON_DSVW, (helper) -> {
                helper.setScanAppType(CONFIGURATION, FINGERPRINT, PMTAINT);
                helper.isUseEntryAnalysisPoint(true);
                helper.isUsePublicAnalysisMethod(true);
                helper.setIsDownloadDependencies(true);
            });

            generateData(destination.toPath(), CSHARP_WEBGOAT, (helper) -> {
                helper.setScanAppType(CSHARP, CONFIGURATION, FINGERPRINT, PMTAINT);
                helper.isUseEntryAnalysisPoint(true);
                helper.isUsePublicAnalysisMethod(true);
                helper.setIsDownloadDependencies(true);
            });

            generateData(destination.toPath(), JAVASCRIPT_VNWA, (helper) -> {
                helper.setScanAppType(JAVASCRIPT, CONFIGURATION, FINGERPRINT, PMTAINT);
                helper.isUseEntryAnalysisPoint(true);
                helper.isUsePublicAnalysisMethod(true);
                helper.setIsDownloadDependencies(false);
            });

            generateData(destination.toPath(), JAVA_APP01, (helper) -> {
                helper.setScanAppType(JAVA, CONFIGURATION, FINGERPRINT, PMTAINT);
                helper.isUseEntryAnalysisPoint(true);
                helper.isUsePublicAnalysisMethod(true);
                helper.setIsDownloadDependencies(true);
            });

            generateData(destination.toPath(), JAVA_OWASP_BENCHMARK, (helper) -> {
                helper.setScanAppType(JAVA, PMTAINT);
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

            generateData(destination.toPath(), PHP_SMOKE, (helper) -> {
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
