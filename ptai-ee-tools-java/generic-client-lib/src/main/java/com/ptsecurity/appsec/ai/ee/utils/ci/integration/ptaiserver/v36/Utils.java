package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.microsoft.signalr.HubConnection;
import com.microsoft.signalr.HubConnectionBuilder;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.ptai.server.systemmanagement.v36.HealthCheck;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Messages;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.CertificateHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.UrlHelper;
import io.reactivex.Single;
import lombok.*;
import lombok.experimental.Accessors;
import lombok.extern.java.Log;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import org.apache.commons.lang3.StringUtils;
import org.joor.Reflect;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;

@Slf4j
public class Utils extends BaseClient {
    public EnterpriseLicenseData getLicenseData() throws ApiException {
        return callApi(() -> licenseApi.apiLicenseGet(), "PT AI license information retrieve failed");
    }

    public HealthCheck healthCheck() throws ApiException {
        return callApi(() -> healthCheckApi.healthSummaryGet(), "PT AI health check failed");
    }

    public List<ReportTemplateModel> getReportTemplates(@NonNull String locale) throws ApiException {
        return callApi(
                () -> reportsApi.apiReportsTemplatesGet(locale, false),
                "PT AI report templates list read failed");
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
        com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.Project project = callApi(
                () -> projectsApi.apiProjectsProjectIdGet(id),
                "PT AI project search failed");
        return (null == project) ? null : project.getName();
    }

    public File generateReport(
            @NonNull final UUID projectId, @NonNull final UUID scanResultId,
            @NonNull final UUID template, @NonNull final ReportFormatType type, @NonNull final String locale) throws ApiException {
        ReportGenerateModel model = new ReportGenerateModel()
                .parameters(new UserReportParameters()
                        .includeDFD(true)
                        .includeGlossary(true)
                        .formatType(type)
                        .reportTemplateId(template)
                        .saveAsPath(""))
                .scanResultId(scanResultId)
                .projectId(projectId)
                .localeId(locale);
        fine("Generating report for project %s, scan result %s. Report template %s, type %s, locale %s", projectId, scanResultId, template, type, locale);
        return callApi(
                () -> reportsApi.apiReportsGeneratePost(model),
                "Report generation failed");
    }

    public File generateReport(
            @NonNull final UUID projectId, @NonNull final UUID scanResultId,
            @NonNull final String template,
            @NonNull final String locale,
            @NonNull final ReportFormatType type) throws ApiException {
        List<ReportTemplateModel> templates = getReportTemplates(locale);
        ReportTemplateModel templateModel = templates.stream().filter(t -> template.equalsIgnoreCase(t.getName())).findAny().orElse(null);
        if (null == templateModel)
            throw ApiException.raise("Report generation failed", new IllegalArgumentException("PT AI template " + template + " not found"));
        return generateReport(projectId, scanResultId, templateModel.getId(), type, locale);
    }

    public UUID latestScanResult(@NonNull final UUID projectId) {
        ScanResult scanResult = callApi(
                () -> projectsApi.apiProjectsProjectIdScanResultsLastGet(projectId),
                "PT AI project latest scan result search failed");
        return (null == scanResult) ? null : scanResult.getId();
    }

    @Accessors(fluent = true, chain = true)
    @Getter @Setter
    @NoArgsConstructor
    public static class TestResult {
        public enum State {
            OK, WARNING, ERROR
        }

        @NonNull
        protected State state = State.ERROR;
        @NonNull
        protected String text = "";
    }

    public TestResult testConnection() throws ApiException {
        TestResult result = new TestResult();
        if (StringUtils.isEmpty(url)) {
            result.text(Messages.validator_check_serverUrl_empty());
            return result;
        }

        boolean error = false;
        boolean warning = !UrlHelper.checkUrl(url);

        String details = "";
        HealthCheck healthCheck = healthCheck();
        if (null == healthCheck || null == healthCheck.getServices()) {
            details += Messages.validator_test_server_health_empty();
            error = true;
        } else {
            long total = healthCheck.getServices().size();
            long healthy = healthCheck.getServices().stream()
                    .filter(s -> "Healthy".equalsIgnoreCase(s.getStatus()))
                    .count();
            details += Messages.validator_test_server_health_success(healthy, total);
            if (0 == healthy) warning = true;
        }
        details += ", ";
        EnterpriseLicenseData licenseData = getLicenseData();
        if (null == licenseData) {
            details += Messages.validator_test_server_license_empty();
            error = true;
        } else {
            details += Messages.validator_test_server_license_success(
                    licenseData.getLicenseNumber(),
                    licenseData.getStartDate(), licenseData.getEndDate());
            if (!licenseData.getIsValid()) warning = true;
        }
        result.text(details);
        return error
                ? result.state(TestResult.State.ERROR)
                : warning
                ? result.state(TestResult.State.WARNING)
                : result.state(TestResult.State.OK);
    }
}
