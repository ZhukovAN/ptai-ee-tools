package com.ptsecurity.appsec.ai.ee.utils.ci.integration.client;

import com.ptsecurity.appsec.ai.ee.server.integration.rest.test.BaseIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;

public class BaseClientIT extends BaseIT {
    protected static ConnectionSettings CONNECTION_SETTINGS = ConnectionSettings.builder()
            .url(BaseIT.URL)
            .token(BaseIT.TOKEN)
            .caCertsPem("")
            .insecure(true)
            .build();
}
