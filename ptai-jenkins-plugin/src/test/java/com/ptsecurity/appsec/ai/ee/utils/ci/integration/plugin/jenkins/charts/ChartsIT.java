package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.server.api.exceptions.ApiHelper;
import com.ptsecurity.appsec.ai.ee.server.api.v36.converters.IssuesConverter;
import com.ptsecurity.appsec.ai.ee.server.api.v36.IssuesModelJsonHelper;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractToolIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.IssuesModelHelper;
import lombok.SneakyThrows;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool.call;

@DisplayName("AST results charts generation integration tests")
@Tag("integration")
class ChartsIT extends AbstractToolIT {
    @DisplayName("Generate vulnerability level distribution chart for randomly chosen scan result")
    @Test
    @SneakyThrows
    public void test() {
        // Prepare date -> issues map
        List<Pair<Integer, com.ptsecurity.appsec.ai.ee.scan.result.ScanResult>> issuesModelList = new ArrayList<>();
        // Get random scan result
        ScanResult randomScanResult = getRandomScanResult();
        Assertions.assertNotNull(randomScanResult, "Randomly chosen scan result is null");
        // Get all scan results for random project
        List<ScanResult> projectScanResults = projectsApi.apiProjectsProjectIdScanResultsGet(randomScanResult.getProjectId(), AuthScopeType.ACCESSTOKEN);
        projectScanResults.sort(Comparator.comparing(ScanResult::getScanDate));
        int counter = 0;
        for (ScanResult scanResult : projectScanResults) {
            ScanResult scanResultV36 = ApiHelper.call(
                    () -> projectsApi.apiProjectsProjectIdScanResultsScanResultIdGet(scanResult.getProjectId(), scanResult.getId()),
                    "Get project scan result failed");
            V36ScanSettings scanSettingsV36 = ApiHelper.call(
                    () -> projectsApi.apiProjectsProjectIdScanSettingsScanSettingsIdGet(scanResult.getProjectId(), scanResult.getSettingsId()),
                    "Get project scan settings failed");

            File json = projectsApi.apiProjectsProjectIdScanResultsScanResultIdIssuesGet(scanResult.getProjectId(), scanResult.getId(), null);
            IssuesModel issuesModelV36 = IssuesModelJsonHelper.parse(new FileInputStream(json));
            AbstractTool.call(
                    json::delete,
                    "Temporal file " + json.getPath() + " delete failed", true);
            issuesModelList.add(new ImmutablePair<>(counter++, IssuesConverter.convert(scanResultV36, issuesModelV36, scanSettingsV36)));
        }

        StackedAreaChartDataModel model = StackedAreaChartDataModel.create(issuesModelList);
        String modelJson = new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(model);
        System.out.println(modelJson);
   }

    @DisplayName("Load OWASP bricks scan result")
    @Test
    @SneakyThrows
    public void downloadVersatileResults() {
        Optional<Project> bricksProject = projectsApi.apiProjectsGet(true).stream()
                .filter(p -> p.getName().equalsIgnoreCase("Bricks"))
                .findAny();
        Assertions.assertTrue(bricksProject.isPresent(), "OWASP Bricks project not found");
        List<ScanResult> projectScanResults = projectsApi.apiProjectsProjectIdScanResultsGet(bricksProject.get().getId(), AuthScopeType.ACCESSTOKEN);
        Assertions.assertFalse(
                null == projectScanResults || projectScanResults.isEmpty() ,
                "OWASP Bricks scan results not found");
        // Sort scan results
        projectScanResults.sort((r1, r2) -> - r1.getScanDate().compareTo(r2.getScanDate()));
        // Get latest scan result
        ScanResult scanResult = projectScanResults.get(0);
        Assertions.assertNotNull(scanResult, "Latest scan result is null");
        File json = projectsApi.apiProjectsProjectIdScanResultsScanResultIdIssuesGet(scanResult.getProjectId(), scanResult.getId(), null);
        IssuesModel issues = IssuesModelHelper.parse(new FileInputStream(json));
        AbstractTool.call(
                () -> json.delete(),
                "Temporal file " + json.getPath() + " delete failed", true);
    }
}
