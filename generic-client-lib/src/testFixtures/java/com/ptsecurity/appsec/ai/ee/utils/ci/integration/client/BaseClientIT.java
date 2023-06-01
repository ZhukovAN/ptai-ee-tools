package com.ptsecurity.appsec.ai.ee.utils.ci.integration.client;

import com.ptsecurity.appsec.ai.ee.server.integration.rest.BaseIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.TokenCredentials;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ProjectTasks;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;

import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;

public abstract class BaseClientIT extends BaseIT {
    protected static ProjectTasks projectTasks;

    @SneakyThrows
    @BeforeAll
    public static void init() {
        BaseIT.init();
        AbstractApiClient client = Assertions.assertDoesNotThrow(() -> Factory.client(CONNECTION_SETTINGS()));
        projectTasks = new Factory().projectTasks(client);
    }

    public static ConnectionSettings CONNECTION_SETTINGS() {
        return ConnectionSettings.builder()
                .url(CONNECTION().getUrl())
                .credentials(new TokenCredentials(CONNECTION().getToken()))
                .caCertsPem(CONNECTION().getCaPem())
                .insecure(CONNECTION().isInsecure())
                .build();
    }
}
