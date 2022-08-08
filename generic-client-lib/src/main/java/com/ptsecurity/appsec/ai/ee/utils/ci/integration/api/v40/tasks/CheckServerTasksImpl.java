package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v40.tasks;

import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.server.v40.projectmanagement.model.EnterpriseLicenseData;
import com.ptsecurity.appsec.ai.ee.server.v40.systemmanagement.model.HealthCheckSummaryResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.CheckServerTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.UrlHelper;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import static com.ptsecurity.appsec.ai.ee.server.v40.systemmanagement.model.HealthStatus.HEALTHY;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

public class CheckServerTasksImpl extends AbstractTaskImpl implements CheckServerTasks {
    public CheckServerTasksImpl(@NonNull final AbstractApiClient client) {
        super(client);
    }

    @Override
    public ServerCheckResult check() throws GenericException {
        ServerCheckResult result = new ServerCheckResult();
        if (StringUtils.isEmpty(client.getConnectionSettings().getUrl())) {
            result.add(Resources.i18n_ast_settings_server_url_message_empty());
            return result;
        }

        boolean error = false;
        boolean warning = !UrlHelper.checkUrl(client.getConnectionSettings().getUrl());

        HealthCheckSummaryResult healthCheck = call(client.getHealthCheckApi()::healthSummaryGet, "PT AI health check failed");
        if (null == healthCheck || null == healthCheck.getServices()) {
            result.add(Resources.i18n_ast_settings_server_check_health_empty());
            error = true;
        } else {
            long total = healthCheck.getServices().size();
            long healthy = healthCheck.getServices().stream()
                    .filter(s -> HEALTHY.equals(s.getStatus()))
                    .count();
            result.add(Resources.i18n_ast_settings_server_check_health_success(healthy, total));
            if (0 == healthy) warning = true;
        }
        EnterpriseLicenseData licenseData = call(client.getLicenseApi()::apiLicenseGet, "PT AI license information retrieve failed");
        if (null == licenseData) {
            result.add(Resources.i18n_ast_settings_server_check_license_sentinel_empty());
            error = true;
        } else {
            result.add(Resources.i18n_ast_settings_server_check_license_sentinel_success(
                    licenseData.getLicenseNumber(),
                    licenseData.getStartDate(), licenseData.getEndDate()));
            if (Boolean.FALSE.equals(licenseData.getIsValid())) warning = true;
        }
        return error
                ? result.setState(ServerCheckResult.State.ERROR)
                : warning
                ? result.setState(ServerCheckResult.State.WARNING)
                : result.setState(ServerCheckResult.State.OK);
    }
}
