package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v42.tasks;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v42.ApiClient;
import lombok.NonNull;

public abstract class AbstractTaskImpl extends AbstractTool {
    @NonNull
    protected ApiClient client;

    public AbstractTaskImpl(@NonNull final AbstractApiClient client) {
        this.client = (ApiClient) client;
        advancedSettings = client.getAdvancedSettings();
    }
}
