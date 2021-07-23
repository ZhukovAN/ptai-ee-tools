package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseClientIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.CheckServerTasks;
import lombok.SneakyThrows;
import org.junit.jupiter.api.*;

@DisplayName("Test dynamic API client functions")
@Tag("integration")
public class VersionInfoIT extends BaseClientIT {
    protected ConnectionSettings connectionSettings = null;

    @BeforeEach
    public void pre() {
        connectionSettings = ConnectionSettings.builder()
                .url(CONNECTION_SETTINGS.getUrl())
                .token(CONNECTION_SETTINGS.getToken())
                .insecure(CONNECTION_SETTINGS.isInsecure())
                .caCertsPem(CONNECTION_SETTINGS.getCaCertsPem())
                .build();
    }
    @SneakyThrows
    @Test
    @DisplayName("Check PT AI server status using insecure connection")
    public void checkInsecureConnection() {
        AbstractApiClient client = Assertions.assertDoesNotThrow(() -> Factory.client(connectionSettings));

        CheckServerTasks checkServerTasks = new Factory().checkServerTasks(client);
        ServerCheckResult serverCheckResult = checkServerTasks.check();
        Assertions.assertEquals(ServerCheckResult.State.OK, serverCheckResult.getState());

        connectionSettings.setInsecure(false);
        Assertions.assertThrows(GenericException.class, () -> Factory.client(connectionSettings));
    }

    @SneakyThrows
    @Test
    @DisplayName("Check PT AI server status using secure connection")
    public void checkSecureConnection() {
        connectionSettings.setInsecure(false);
        connectionSettings.setCaCertsPem(CA);
        AbstractApiClient client = Assertions.assertDoesNotThrow(() -> Factory.client(connectionSettings));

        CheckServerTasks checkServerTasks = new Factory().checkServerTasks(client);
        ServerCheckResult serverCheckResult = checkServerTasks.check();
        Assertions.assertEquals(ServerCheckResult.State.OK, serverCheckResult.getState());

        connectionSettings.setCaCertsPem(null);
        Assertions.assertThrows(GenericException.class, () -> Factory.client(connectionSettings));

    }

}
