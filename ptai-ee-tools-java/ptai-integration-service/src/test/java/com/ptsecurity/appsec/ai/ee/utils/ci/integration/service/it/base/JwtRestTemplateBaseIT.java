package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it.base;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.jwt.JwtResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.utils.JwtRestTemplate;
import io.jsonwebtoken.Jwts;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.test.web.servlet.MvcResult;

import javax.net.ssl.SSLContext;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

public class JwtRestTemplateBaseIT extends BaseIT {
    protected OAuth2ProtectedResourceDetails integrationServer(String clientId, String userName) {
        // Setup protected resource details
        ResourceOwnerPasswordResourceDetails details = new ResourceOwnerPasswordResourceDetails();
        details.setClientId(clientId);
        details.setClientSecret(clientSecret);
        details.setUsername(userName);
        details.setPassword(password);
        details.setGrantType("password");
        details.setScope(Arrays.asList("read", "write", "trust"));
        details.setAccessTokenUri(rootUrl + apiAccessToken);

        return details;
    }

    // Create RestTemplate client that supports JWT
    public OAuth2RestTemplate integrationServerRestTemplate(String clientId, String userName) throws Exception {
        // Setup protected resource details
        ResourceOwnerPasswordResourceDetails details = new ResourceOwnerPasswordResourceDetails();
        details.setClientId(clientId);
        details.setClientSecret(clientSecret);
        details.setUsername(userName);
        details.setPassword(password);
        details.setGrantType("password");
        details.setScope(Arrays.asList("read", "write", "trust"));
        details.setAccessTokenUri(rootUrl + apiAccessToken);
        // Setup Http request factory with custom trusted certificates
        ClientHttpRequestFactory factory = factory();

        OAuth2RestTemplate template = new JwtRestTemplate(details, new DefaultOAuth2ClientContext());
        template.setRequestFactory(factory);
        // template.setInterceptors(Collections.singletonList(new JwtAuthenticationBase.JsonMimeInterceptor()));

        // OAuth2RestTemplate creates internal RestTemplate for token acquisition so setting Request Factory isn't enough
        ResourceOwnerPasswordAccessTokenProvider provider = new ResourceOwnerPasswordAccessTokenProvider();
        provider.setRequestFactory(factory);
        template.setAccessTokenProvider(provider);

        return template;
    }
    protected JwtResponse authenticateUser(String userName) throws Exception {
        Map<String, String> authData = new HashMap<>();
        authData.put("username", userName);
        authData.put("password", password);
        authData.put("grant_type", "password");

        String auth = authData.keySet().stream()
                .map(key -> key + "=" + encodeValue(authData.get(key)))
                .collect(Collectors.joining("&"));

        MvcResult result = mvc.perform(post(apiAccessToken)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .content(auth)
                .with(httpBasic(clientIdFast, clientSecret)))
                .andExpect(status().isOk()).andReturn();
        String jwtResponse = result.getResponse().getContentAsString();
        JwtResponse response = new ObjectMapper().readValue(jwtResponse, JwtResponse.class);
        Jwts.parser().setSigningKey(jwtPublicKey).parse(response.getAccessToken());
        return response;
    }

    public ClientHttpRequestFactory factory() throws Exception {
        // Setup custom trusted certificates
        SSLContext sslContext = new SSLContextBuilder()
                .loadTrustMaterial(
                        trustStore.getURL(),
                        trustStorePassword.toCharArray()
                ).build();
        SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext);
        HttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(socketFactory).build();
        HttpComponentsClientHttpRequestFactory factory =
                new HttpComponentsClientHttpRequestFactory(httpClient);
        return factory;
    }

    protected String encodeValue(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
}
