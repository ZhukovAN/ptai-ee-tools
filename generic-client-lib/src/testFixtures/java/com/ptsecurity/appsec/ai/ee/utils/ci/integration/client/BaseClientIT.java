package com.ptsecurity.appsec.ai.ee.utils.ci.integration.client;

import com.ptsecurity.appsec.ai.ee.server.integration.rest.test.BaseIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.TokenCredentials;

public abstract class BaseClientIT extends BaseIT {
    public static ConnectionSettings CONNECTION_SETTINGS() {
        return ConnectionSettings.builder()
                .url(CONNECTION().getUrl())
                .credentials(new TokenCredentials(CONNECTION().getToken()))
                .caCertsPem(CONNECTION().getCaPem())
                .insecure(CONNECTION().isInsecure())
                .build();
    }
}
