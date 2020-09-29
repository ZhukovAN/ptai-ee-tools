package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.v36.*;
import com.ptsecurity.appsec.ai.ee.ptai.server.systemmanagement.v36.HealthCheck;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import lombok.NonNull;
import lombok.extern.java.Log;

import java.util.*;

@Log
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
}
