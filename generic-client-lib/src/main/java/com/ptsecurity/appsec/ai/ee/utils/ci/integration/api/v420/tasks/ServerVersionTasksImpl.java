package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v420.tasks;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;

import static com.ptsecurity.misc.tools.helpers.CallHelper.call;

@Slf4j
public class ServerVersionTasksImpl extends AbstractTaskImpl implements ServerVersionTasks {
    public ServerVersionTasksImpl(@NonNull final AbstractApiClient client) {
        super(client);
    }

    @Override
    public Map<Component, String> current() throws GenericException {
        Map<Component, String> res = new HashMap<>();
        for (Component component : Component.values()) {
            log.debug("Getting current {} component version", component.getValue());
            String version = call(
                    () -> client.getLegacyVersionApi().apiVersionsPackageCurrentGet(),
                    "PT AI server API current version get failed");
            log.debug("Current version: {}", version);
            res.put(component, version);
        }
        return res;
    }
}
