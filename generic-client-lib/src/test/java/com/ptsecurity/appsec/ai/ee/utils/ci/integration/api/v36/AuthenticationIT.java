package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.v36;

import com.ptsecurity.appsec.ai.ee.ServerCheckResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.Factory;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseClientIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.JwtResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.CheckServerTasks;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import lombok.SneakyThrows;
import org.joor.Reflect;
import org.junit.jupiter.api.*;

import java.security.Key;
import java.time.Duration;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;
import static org.joor.Reflect.onClass;

@DisplayName("Test API client authentication")
@Tag("integration")
public class AuthenticationIT extends BaseClientIT {
    protected ConnectionSettings connectionSettings = null;

    @BeforeEach
    public void pre() {
        connectionSettings = ConnectionSettings.builder()
                .url(CONNECTION_SETTINGS.getUrl())
                .credentials(CONNECTION_SETTINGS.getCredentials())
                .insecure(CONNECTION_SETTINGS.isInsecure())
                .caCertsPem(CONNECTION_SETTINGS.getCaCertsPem())
                .build();
    }

    @SneakyThrows
    @Test
    @DisplayName("Check implicit JWT refresh during API calls")
    public void checkAutoJwtRefresh() {
        ApiClient client = new ApiClient(connectionSettings.validate());
        // Initialize all API clients with URL, timeouts, SSL settings etc.
        client.init();
        client.authenticate();

        JwtResponse initialJwtResponse = client.getApiJwt();
        int signatureIdx = initialJwtResponse.getAccessToken().lastIndexOf('.');
        String withoutSignature = initialJwtResponse.getAccessToken().substring(0, signatureIdx + 1);
        Jwt<Header, Claims> initialJwt = Jwts.parser().parseClaimsJwt(withoutSignature);
        String version = Assertions.assertDoesNotThrow(
                () -> client.getVersionApi().apiVersionGetCurrentGet(ServerVersionTasks.Component.AIE.getValue()),
                "PT AI server component API current version get failed");

        // Wait for access toke expiration
        Duration duration = Duration.between(initialJwt.getBody().getNotBefore().toInstant(), initialJwt.getBody().getExpiration().toInstant());
        duration = duration.plusSeconds(5);
        Thread.sleep(duration.toMillis());

        String versionAfterRefresh = Assertions.assertDoesNotThrow(
                () -> client.getVersionApi().apiVersionGetCurrentGet(ServerVersionTasks.Component.AIE.getValue()),
                "PT AI server component API current version get failed");

        Assertions.assertEquals(versionAfterRefresh, version);

        JwtResponse freshJwtResponse = client.getApiJwt();
        signatureIdx = freshJwtResponse.getAccessToken().lastIndexOf('.');
        withoutSignature = freshJwtResponse.getAccessToken().substring(0, signatureIdx + 1);
        Jwt<Header, Claims> freshJwt = Jwts.parser().parseClaimsJwt(withoutSignature);
        Assertions.assertTrue(freshJwt.getBody().getExpiration().after(initialJwt.getBody().getExpiration()));
    }
}
