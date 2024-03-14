package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v470;

import com.google.gson.reflect.TypeToken;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.scan.reports.Reports.RawData;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjV13ScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.aiproj.AiprojV13;
import com.ptsecurity.appsec.ai.ee.server.integration.rest.Environment;
import com.ptsecurity.appsec.ai.ee.server.v470.api.ApiResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.JsonAstJobIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v470.ApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseClientIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.AbstractJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.GenericAstJob;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.export.RawJson;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs.subjobs.state.FailIfAstFailed;
import com.ptsecurity.misc.tools.TempFile;
import com.ptsecurity.misc.tools.helpers.ArchiveHelper;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import okhttp3.Call;
import org.apache.commons.compress.utils.Sets;
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
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief.ApiVersion.*;
import static com.ptsecurity.appsec.ai.ee.scan.settings.UnifiedAiProjScanSettings.ScanModule.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.ID.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.ProjectTemplate.getTemplate;
import static com.ptsecurity.misc.tools.helpers.BaseJsonHelper.createObjectMapper;

@Slf4j
@DisplayName("Test PT AI 4.7 REST API data structures")
@Tag("development")
@Environment(enabledFor = { V470 })
public class RestApiDataStructuresIT extends BaseClientIT {

    @SuppressWarnings("ResultOfMethodCallIgnored")
    @SneakyThrows
    protected void generateData(@NonNull final Path destination, @NonNull final ProjectTemplate.ID templateId, @NonNull final Consumer<UnifiedAiProjScanSettings> modifySettings) {
        RawData rawData = RawData.builder()
                .fileName(UUID.randomUUID() + ".json")
                .build();

        ProjectTemplate projectTemplate = getTemplate(templateId);
//        projectTemplate.getSettings().setVetsion(AiprojV13.Version._1_3);
        UnifiedAiProjScanSettings settings = UnifiedAiProjScanSettings.loadSettings(projectTemplate.getSettings().toJson());
        modifySettings.accept(settings);

        GenericAstJob astJob = JsonAstJobIT.JsonAstJobImpl.builder()
                .async(false)
                .fullScanMode(true)
                .connectionSettings(CONNECTION_SETTINGS())
                .console(System.out)
                .sources(projectTemplate.getCode())
                .destination(destination)
                // As we directly pass scan settings there's no need to call Project's setup method
                .jsonSettings(settings.toJson())
                .build();
        RawJson.builder().owner(astJob).rawData(rawData).build().attach(astJob);
        FailIfAstFailed.builder().build().attach(astJob);
        AbstractJob.JobExecutionResult res = astJob.execute();
        Assertions.assertEquals(res, AbstractJob.JobExecutionResult.SUCCESS);

        File json = destination.resolve(rawData.getFileName()).toFile();
        Assertions.assertTrue(json.exists());
        ScanResult scanResult = createObjectMapper().readValue(json, ScanResult.class);

        ConnectionSettings connectionSettings = CONNECTION_SETTINGS().validate();
        com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v470.ApiClient client = new ApiClient(connectionSettings);
        // Initialize all API clients with URL, timeouts, SSL settings etc.
        client.init();
        client.authenticate();

        Path jsons = destination.resolve("v470").resolve("json");
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
        FileUtils.writeStringToFile(scanSettingsDir.resolve(projectTemplate.getName() + ".json").toFile(), scanSettingsResponse.getData(), StandardCharsets.UTF_8);

        call = client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdGetCall(scanResult.getProjectId(), scanResult.getId(), null);
        ApiResponse<String> scanResultResponse = client.getProjectsApi().getApiClient().execute(call, stringType);
        FileUtils.writeStringToFile(scanResultDir.resolve(projectTemplate.getName() + ".json").toFile(), scanResultResponse.getData(), StandardCharsets.UTF_8);

        call = client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdIssuesGetCall(scanResult.getProjectId(), scanResult.getId(), null);
        ApiResponse<String> scanIssuesResponse = client.getProjectsApi().getApiClient().execute(call, stringType);
        FileUtils.writeStringToFile(issuesModelDir.resolve(projectTemplate.getName() + ".json").toFile(), scanIssuesResponse.getData(), StandardCharsets.UTF_8);

        for (Reports.Locale locale : Reports.Locale.values()) {
            log.trace("Getting issues data using {} locale", locale);
            call = client.getProjectsApi().apiProjectsProjectIdScanResultsScanResultIdIssuesHeadersGetCall(scanResult.getProjectId(), scanResult.getId(), locale.getValue(), null);
            ApiResponse<String> scanIssuesHeadersResponse = client.getProjectsApi().getApiClient().execute(call, stringType);
            try (TempFile tempFile = TempFile.createFile()) {
                FileUtils.writeStringToFile(tempFile.toFile(), scanIssuesHeadersResponse.getData(), StandardCharsets.UTF_8);
                log.debug("Localized ({}) issue headers stored to temp file {}", locale, tempFile.toFile().getAbsolutePath());
                Path sevenZip = issuesModelDir.resolve(projectTemplate.getName() + "." + locale.getLocale().getLanguage() + ".json.7z");
                ArchiveHelper.packData7Zip(sevenZip, FileUtils.readFileToByteArray(tempFile.toFile()));
            }
        }
    }

    @SneakyThrows
    @Test
    public void generateRestApiDataStructures() {
        try (TempFile destination = TempFile.createFolder()) {
            generateData(destination.toPath(), C_SARD_101_000_149_064, (settings) -> {
                settings.setScanModules(Stream.of(CONFIGURATION, STATICCODEANALYSIS, PATTERNMATCHING).collect(Collectors.toSet()));
            });

            generateData(destination.toPath(), PYTHON_DSVW, (settings) -> {
                settings.setScanModules(Stream.of(CONFIGURATION, STATICCODEANALYSIS, PATTERNMATCHING).collect(Collectors.toSet()));
            });

            generateData(destination.toPath(), CSHARP_WEBGOAT, (settings) -> {
                settings.setScanModules(Stream.of(CONFIGURATION, STATICCODEANALYSIS, PATTERNMATCHING).collect(Collectors.toSet()));
            });

            generateData(destination.toPath(), JAVASCRIPT_VNWA, (settings) -> {
                settings.setScanModules(Stream.of(CONFIGURATION, STATICCODEANALYSIS, PATTERNMATCHING).collect(Collectors.toSet()));
            });

            generateData(destination.toPath(), JAVA_APP01, (settings) -> {
                settings.setScanModules(Stream.of(CONFIGURATION, STATICCODEANALYSIS, PATTERNMATCHING).collect(Collectors.toSet()));
            });

            generateData(destination.toPath(), JAVA_OWASP_BENCHMARK, (settings) -> {
                settings.setScanModules(Stream.of(STATICCODEANALYSIS, PATTERNMATCHING).collect(Collectors.toSet()));
            });

            generateData(destination.toPath(), PHP_OWASP_BRICKS, (settings) -> {
                settings.setScanModules(Stream.of(CONFIGURATION, STATICCODEANALYSIS, PATTERNMATCHING).collect(Collectors.toSet()));
            });

            generateData(destination.toPath(), PHP_SMOKE, (settings) -> {
                settings.setScanModules(Stream.of(CONFIGURATION, STATICCODEANALYSIS, PATTERNMATCHING).collect(Collectors.toSet()));
            });

            log.trace("REST API data generation complete");
        }
    }
}
