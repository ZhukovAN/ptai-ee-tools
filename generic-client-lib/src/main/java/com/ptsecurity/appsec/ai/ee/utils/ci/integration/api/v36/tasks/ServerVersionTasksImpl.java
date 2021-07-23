package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.tasks;

import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.server.v36.projectmanagement.model.EnterpriseLicenseData;
import com.ptsecurity.appsec.ai.ee.server.v36.systemmanagement.model.HealthCheck;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.CheckServerTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.UrlHelper;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

public class ServerVersionTasksImpl extends AbstractTaskImpl implements ServerVersionTasks {
    private static final String PRODUCT = "aie";

    public ServerVersionTasksImpl(@NonNull final AbstractApiClient client) {
        super(client);
    }

    @Override
    public String current() throws GenericException {
        return call(
                () -> client.getVersionApi().apiVersionGetCurrentGet(PRODUCT),
                "PT AI server API current version get failed");
    }

    @Override
    public String latest() throws GenericException {
        return call(
                () -> client.getVersionApi().apiVersionGetLatestGet(PRODUCT),
                "PT AI server API latest version get failed");
    }
}
