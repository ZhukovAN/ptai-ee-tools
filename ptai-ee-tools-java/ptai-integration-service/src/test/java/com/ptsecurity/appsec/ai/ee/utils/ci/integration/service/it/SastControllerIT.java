package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.Client;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.controller.SastController;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it.base.BaseIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.service.SastService;
import org.junit.jupiter.api.*;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.util.Optional;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@DisplayName("Test JWT authentication / authorization using OkHttp3")
public class SastControllerIT extends BaseIT {
    @MockBean
    protected SastService sastService;

    @InjectMocks
    protected SastController sastController;

    protected static final String apiScanUiManaged = "/api/sast/scan-ui-managed";

    @Test
    @DisplayName("Test SAST API access using JWT")
    public void testSastControllerApi() throws Exception {
        Client client = new Client();
        client.setUrl("https://localhost:" + port);
        client.setClientId(clientIdFast);
        client.setClientSecret(clientSecret);
        client.setUserName(loginTestUser);
        client.setPassword(password);
        client.init();

        // Mockito.doReturn(Optional.of(2020)).when(sastService).scanUiManaged("projectName", "nodeName");
        Integer randomValue = new Random().nextInt();
        Mockito.when(sastService.scanUiManaged("projectName", "nodeName")).thenReturn(Optional.of(randomValue));

        Integer id = client.getSastApi().scanUiManagedUsingPOST("projectName", "nodeName");
        assertEquals(id, randomValue);

        String token = client.getSastApi().getCurrentJwt().getAccessToken();
        waitForExpiration("Waiting for JWT expiration", token);

        client.getSastApi().scanUiManagedUsingPOST("projectName", "nodeName");
        String newToken = client.getSastApi().getCurrentJwt().getAccessToken();
        assertNotEquals(token, newToken);
    }
}
