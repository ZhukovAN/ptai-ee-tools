package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36.tasks;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;

@Slf4j
public class ServerVersionTasksImpl extends AbstractTaskImpl implements ServerVersionTasks {
    public ServerVersionTasksImpl(@NonNull final AbstractApiClient client) {
        super(client);
    }

    @Override
    public Map<Component, String> current() throws GenericException {
        Map<Component, String> res = new HashMap<>();
        for (Component component : Component.values()) {
            log.debug("Getting currrent {} component version", component.getValue());
            String version = call(
                    () -> client.getVersionApi().apiVersionGetCurrentGet(component.getValue()),
                    "PT AI server component API current version get failed");
            log.debug("{} current version: ", version);
            res.put(component, version);
        }
        return res;
    }

    @Override
    public Map<Component, String> latest() throws GenericException {
        Map<Component, String> res = new HashMap<>();
        for (Component component : Component.values()) {
            log.debug("Getting latest {} component version", component.getValue());
            String version = call(
                    () -> client.getVersionApi().apiVersionGetLatestGet(component.getValue()),
                    "PT AI server component API current version get failed");
            log.debug("{} latest version: ", version);
            res.put(component, version);
        }
        return res;
    }
}
