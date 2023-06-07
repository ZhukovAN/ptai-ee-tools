package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.client.BaseClientIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.ServerVersionTasks;
import com.ptsecurity.misc.tools.Jwt;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;

import java.time.Duration;
import java.util.Map;

@DisplayName("Test API client authentication")
@Tag("integration")
@Slf4j
public class AuthenticationIT extends BaseClientIT {
    protected ConnectionSettings connectionSettings = null;

    @BeforeEach
    public void pre() {
        connectionSettings = CONNECTION_SETTINGS();
    }

    @SneakyThrows
    @Test
    @Tag("slow")
    @DisplayName("Check implicit JWT refresh during API calls")
    public void checkAutoJwtRefresh() {
        AbstractApiClient client = Assertions.assertDoesNotThrow(() -> Factory.client(connectionSettings));
        // ApiClient client = new ApiClient(connectionSettings.validate());
        // Initialize all API clients with URL, timeouts, SSL settings etc.
        // client.init();
        // client.authenticate();

        Jwt initialJwtResponse = client.getApiJwt();
        log.trace("Initial authentication using API token: JWT is {}", initialJwtResponse);
        int signatureIdx = initialJwtResponse.getAccessToken().lastIndexOf('.');
        String withoutSignature = initialJwtResponse.getAccessToken().substring(0, signatureIdx + 1);
        // Allow up to five seconds time difference between PT AI client and server to avoid something like PrematureJwtException
        JwtParser parser = Jwts.parserBuilder(). setAllowedClockSkewSeconds(5).build();
        // JwtParser parser = Jwts.parser().setAllowedClockSkewSeconds(5);
        io.jsonwebtoken.Jwt<Header, Claims> initialJwt = parser.parseClaimsJwt(withoutSignature);
        ServerVersionTasks serverVersionTasks = new Factory().serverVersionTasks(client);
        Map<ServerVersionTasks.Component, String> versions = Assertions.assertDoesNotThrow(
                serverVersionTasks::current,
                "PT AI server component API current version get failed");
        Assertions.assertNotNull(versions);
        String version = versions.get(ServerVersionTasks.Component.AIE);
        Assertions.assertNotNull(version);

        // Wait for access toke expiration
        Duration duration = Duration.between(initialJwt.getBody().getNotBefore().toInstant(), initialJwt.getBody().getExpiration().toInstant());
        duration = duration.plusSeconds(60);
        Thread.sleep(duration.toMillis());

        Map<ServerVersionTasks.Component, String> versionsAfterRefresh = Assertions.assertDoesNotThrow(
                serverVersionTasks::current,
                "PT AI server component API current version get failed");
        Assertions.assertNotNull(versionsAfterRefresh);
        Assertions.assertEquals(versionsAfterRefresh.get(ServerVersionTasks.Component.AIE), version);

        Jwt freshJwtResponse = client.getApiJwt();
        log.trace("Subsequent re-authentication using refresh token: JWT is {}", freshJwtResponse);
        signatureIdx = freshJwtResponse.getAccessToken().lastIndexOf('.');
        withoutSignature = freshJwtResponse.getAccessToken().substring(0, signatureIdx + 1);
        io.jsonwebtoken.Jwt<Header, Claims> freshJwt = parser.parseClaimsJwt(withoutSignature);
        Assertions.assertTrue(freshJwt.getBody().getExpiration().after(initialJwt.getBody().getExpiration()));
    }
}
