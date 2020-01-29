package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.jwt.JwtResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it.base.BaseIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it.base.JwtRestTemplateBaseIT;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.utils.JwtRestTemplate;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.junit.jupiter.api.*;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DisplayName("Test JWT authentication / authorization using customized OAuth2RestTemplate")
public class JwtAuthenticationIT extends JwtRestTemplateBaseIT {

    @Test
    @DisplayName("Assert no guest access to admin API")
    public void guestAccessDenied() throws Exception {
        mvc.perform(
                get(apiRandomString)
                        .contentType(MediaType.APPLICATION_JSON)
        ).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Assert admin successful access after authentication")
    public void adminAccessGranted() throws Exception {
        JwtResponse jwt = authenticateUser(loginTestAdmin);
        mvc.perform(
                get(apiRandomString)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt.getAccessToken())
        ).andExpect(status().isOk());
    }

    @Test
    @DisplayName("Assert admin access failed after token expiration")
    public void tokenExpiration() throws Exception {
        JwtResponse jwt = authenticateUser(loginTestAdmin);
        waitForExpiration("Waiting for access token expiration", jwt.getAccessToken());
        mvc.perform(
                get(apiRandomString)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt.getAccessToken())
        ).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Assert admin access failed after token expiration - using RestTemplate")
    public void testUsingRestTemplate() throws Exception {
        RestTemplate restTemplate = new RestTemplate(factory());

        final String baseUrl = "https://localhost:" + port + "/api/ptai-gateway-url";
        URI uri = new URI(baseUrl);

        Exception e = assertThrows(
                HttpClientErrorException.Unauthorized.class,
                () -> { restTemplate.getForEntity(uri, String.class); });
    }

    @Test
    @DisplayName("Assert JWT token refresh process")
    public void testOAuth2RestTemplate() throws Exception {
        OAuth2RestTemplate restTemplate = integrationServerRestTemplate(clientIdFast, loginTestAdmin);

        OAuth2AccessToken token[] = new OAuth2AccessToken[2];
        token[0] = restTemplate.getAccessToken();
        assertNotNull(token[0]);
        Jwt jwt = Jwts.parser().setSigningKey(jwtPublicKey).parse(token[0].getValue());

        ResponseEntity<String> result = restTemplate.getForEntity(rootUrl + apiRandomString, String.class);
        String randomPass = result.getBody();
        assertEquals(randomPass.length(), 32);
        System.out.println(apiRandomString + " result " + randomPass);
        // We shouldn't call restTemplate.getAccessToken() as we need existing one but not try to re-issue
        token[1] = restTemplate.getOAuth2ClientContext().getAccessToken();
        assertEquals(token[0], token[1]);

        // Access token lifetime is 5 seconds so it should expire
        waitForExpiration("Waiting for access token expiration", token[1].getValue());
        result = restTemplate.getForEntity(rootUrl + apiPasswordEncode, String.class, randomPass);
        ResponseEntity<String> result1 = restTemplate.getForEntity(rootUrl + apiPasswordEncode, String.class, randomPass);
        token[0] = restTemplate.getOAuth2ClientContext().getAccessToken();
        assertNotEquals(token[0], token[1]);
        System.out.println(apiPasswordEncode + " result " + result.getBody());

        // Even refresh token expired now but REST call is to be successful as client re-authenticates
        // using client secret
        waitForExpiration("Waiting for refresh token expiration", token[0].getRefreshToken().getValue());
        assertEquals(restTemplate.getForEntity(rootUrl + apiPasswordEncode, String.class, randomPass).getStatusCode(), HttpStatus.OK);
    }
}
