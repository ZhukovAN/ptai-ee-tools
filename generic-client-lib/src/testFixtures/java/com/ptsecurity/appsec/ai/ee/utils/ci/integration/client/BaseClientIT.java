package com.ptsecurity.appsec.ai.ee.utils.ci.integration.client;

import com.ptsecurity.appsec.ai.ee.server.integration.rest.test.BaseIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeAll;

import java.io.InputStream;
import java.util.logging.LogManager;

public class BaseClientIT extends BaseIT {
    protected static ConnectionSettings CONNECTION_SETTINGS = ConnectionSettings.builder()
            .url(BaseIT.URL)
            .token(BaseClientIT.TOKEN)
            .caCertsPem("")
            .insecure(true)
            .build();

    @SneakyThrows
    @BeforeAll
    public static void init() {
        InputStream stream = getResourceStream("logging.properties");
        LogManager.getLogManager().readConfiguration(stream);
    }
}
