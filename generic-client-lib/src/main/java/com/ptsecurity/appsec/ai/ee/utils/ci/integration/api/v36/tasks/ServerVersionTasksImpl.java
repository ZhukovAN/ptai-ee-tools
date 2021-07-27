package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.tasks;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import lombok.NonNull;

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
