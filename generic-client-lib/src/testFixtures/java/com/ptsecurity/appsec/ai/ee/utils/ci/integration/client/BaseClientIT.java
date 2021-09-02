package com.ptsecurity.appsec.ai.ee.utils.ci.integration.client;

import com.ptsecurity.appsec.ai.ee.server.integration.rest.test.BaseIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.TokenCredentials;

public abstract class BaseClientIT extends BaseIT {
    protected static ConnectionSettings CONNECTION_SETTINGS = ConnectionSettings.builder()
            .url(BaseIT.URL)
            .credentials(TokenCredentials.builder().token(BaseIT.TOKEN).build())
            .caCertsPem("")
            .insecure(true)
            .build();
}
