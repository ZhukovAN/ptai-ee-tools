package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.*;
import com.ptsecurity.appsec.ai.ee.ptai.server.v36.systemmanagement.model.HealthCheck;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.UrlHelper;
import lombok.*;
import lombok.experimental.Accessors;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import javax.annotation.Nullable;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
@SuperBuilder
@NoArgsConstructor
@ToString(callSuper = true)
public class Utils extends BaseClient {

    public EnterpriseLicenseData getLicenseData() throws ApiException {
        return callApi(licenseApi::apiLicenseGet, "PT AI license information retrieve failed");
    }

    public HealthCheck healthCheck() throws ApiException {
        return callApi(healthCheckApi::healthSummaryGet, "PT AI health check failed");
    }

    public List<ReportTemplateModel> getReportTemplates(@NonNull Reports.Locale locale) throws ApiException {
        return callApi(
                () -> reportsApi.apiReportsTemplatesGet(locale.getValue(), false),
                "PT AI report templates list read failed");
    }

    /** XML and JSON reports are ignoring template name as those formats are
     * solely dedicated to be used for subsequent automated processing like
     * parsing, uploading to BI etc. But 3.6.1 API doesn't allow to generate
     * report without template ID, so we need to provide API with any
     * template ID. This method searches for templates and returns built-in ID
     * for PlainReport type
     * @param locale PlainReport locale ID
     * @return PlainReport template metadata
     * @throws ApiException Report not found or API call failed
     */
    protected ReportTemplateModel getDummyReportTemplate(@NonNull Reports.Locale locale) throws ApiException {
        List<ReportTemplateModel> templates = callApi(
                () -> reportsApi.apiReportsTemplatesGet(locale.getValue(), false),
                "PT AI report templates list read failed");
        return templates.stream()
                .filter(t -> ReportType.PLAINREPORT.equals(t.getType()))
                .findAny()
                .orElseThrow(() -> ApiException.raise("Built-in PT AI report template missing", new IllegalArgumentException(ReportType.PLAINREPORT.getValue())));
    }

    public UUID searchProject(
            @NonNull final String name) throws ApiException {
        ProjectLight projectLight = callApi(
                () -> projectsApi.apiProjectsLightNameGet(name),
                "PT AI project search failed");
        return (null == projectLight) ? null : projectLight.getId();
    }

    public String searchProject(
            @NonNull final UUID id) throws ApiException {
        com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.Project project = callApi(
                () -> projectsApi.apiProjectsProjectIdGet(id),
                "PT AI project search failed");
        return (null == project) ? null : project.getName();
    }

    public File generateReport(
            @NonNull final UUID projectId, @NonNull final UUID scanResultId,
            @NonNull final UUID template, @NonNull final Reports.Locale locale,
            @NonNull final ReportFormatType type,
            @Nullable final Reports.IssuesFilterEx filters) throws ApiException {
        ReportGenerateModel model = new ReportGenerateModel()
                .parameters(new UserReportParameters()
                        .includeDFD(true)
                        .includeGlossary(true)
                        .useFilters(null != filters)
                        .formatType(type)
                        .reportTemplateId(template)
                        .saveAsPath(""))
                .scanResultId(scanResultId)
                .projectId(projectId)
                .localeId(locale.getValue());
        if (null != filters) model.setFilters(filters.convert());
        fine("Generating report for project %s, scan result %s. Report template %s, type %s, locale %s", projectId, scanResultId, template, type, locale);
        return callApi(
                () -> reportsApi.apiReportsGeneratePost(model),
                "Report generation failed");
    }

    public File generateReport(
            @NonNull final UUID projectId, @NonNull final UUID scanResultId,
            @NonNull final String template,
            @NonNull final Reports.Locale locale,
            @NonNull final ReportFormatType type,
            @Nullable final Reports.IssuesFilterEx filters) throws ApiException {
        List<ReportTemplateModel> templates = getReportTemplates(locale);
        ReportTemplateModel templateModel = templates.stream().filter(t -> template.equalsIgnoreCase(t.getName())).findAny().orElse(null);
        if (null == templateModel || null == templateModel.getId())
            throw ApiException.raise("Report generation failed", new IllegalArgumentException("PT AI template " + template + " not found"));
        return generateReport(projectId, scanResultId, templateModel.getId(), locale, type, filters);
    }

    public UUID latestScanResult(@NonNull final UUID projectId) {
        ScanResult scanResult = callApi(
                () -> projectsApi.apiProjectsProjectIdScanResultsLastGet(projectId),
                "PT AI project latest scan result search failed");
        return (null == scanResult) ? null : scanResult.getId();
    }

    @Getter @Setter
    @NoArgsConstructor
    @Accessors(chain = true, fluent = true)
    public static class TestResult extends ArrayList<String> {
        public enum State {
            OK, WARNING, ERROR
        }

        @NonNull
        protected State state = State.ERROR;

        public String text() {
            return String.join(". ", this);
        }
    }

    public TestResult testConnection() throws ApiException {
        TestResult result = new TestResult();
        if (StringUtils.isEmpty(url)) {
            result.add(Resources.validator_check_serverUrl_empty());
            return result;
        }

        boolean error = false;
        boolean warning = !UrlHelper.checkUrl(url);

        HealthCheck healthCheck = healthCheck();
        if (null == healthCheck || null == healthCheck.getServices()) {
            result.add(Resources.validator_test_server_health_empty());
            error = true;
        } else {
            long total = healthCheck.getServices().size();
            long healthy = healthCheck.getServices().stream()
                    .filter(s -> "Healthy".equalsIgnoreCase(s.getStatus()))
                    .count();
            result.add(Resources.validator_test_server_health_success(healthy, total));
            if (0 == healthy) warning = true;
        }
        EnterpriseLicenseData licenseData = getLicenseData();
        if (null == licenseData) {
            result.add(Resources.validator_test_server_license_empty());
            error = true;
        } else {
            result.add(Resources.validator_test_server_license_success(
                    licenseData.getLicenseNumber(),
                    licenseData.getStartDate(), licenseData.getEndDate()));
            if (Boolean.FALSE.equals(licenseData.getIsValid())) warning = true;
        }
        return error
                ? result.state(TestResult.State.ERROR)
                : warning
                ? result.state(TestResult.State.WARNING)
                : result.state(TestResult.State.OK);
    }

    public File getJsonResult(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws ApiException {
        return callApi(
                () -> projectsApi.apiProjectsProjectIdScanResultsScanResultIdIssuesGet(projectId, scanResultId, null),
                "PT AI project scan status JSON read failed");
    }
}
