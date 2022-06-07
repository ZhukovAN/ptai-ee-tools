package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseClientIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.TokenCredentials;
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
        connectionSettings = CONNECTION_SETTINGS();
    }

    @SneakyThrows
    @Test
    @DisplayName("Check PT AI server status using insecure connection without trusted CA certificates")
    public void checkInsecureConnection() {
        // As we do not know if JRE's truststore contains integration test CA certificates, let's use dummy one
        connectionSettings.setCaCertsPem(DUMMY());
        connectionSettings.setInsecure(true);
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
        AbstractApiClient client = Assertions.assertDoesNotThrow(() -> Factory.client(connectionSettings));

        CheckServerTasks checkServerTasks = new Factory().checkServerTasks(client);
        ServerCheckResult serverCheckResult = checkServerTasks.check();
        Assertions.assertEquals(ServerCheckResult.State.OK, serverCheckResult.getState());

        connectionSettings.setCaCertsPem(getResourceString("keys/root-ca.dummy.org.pem"));
        Assertions.assertThrows(GenericException.class, () -> Factory.client(connectionSettings));
    }

}
