package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.utils;

import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.concurrent.Callable;

public class JwtRestTemplate extends OAuth2RestTemplate {
    public JwtRestTemplate(OAuth2ProtectedResourceDetails resource) {
        super(resource);
    }

    public JwtRestTemplate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext context) {
        super(resource, context);
    }

    protected <V> V callApi(Callable<V> call) throws Exception {
        return call.call();
    }

    @Override
    protected OAuth2AccessToken acquireAccessToken(OAuth2ClientContext oauth2Context)
            throws UserRedirectRequiredException {
        // We drop here only if there's no access token or it is expired (see OAuth2RestTemplate.getAccessToken)
        // OAuth2RestTemplate's implementation doesn't renews access token using refresh_token
        // as it doesn't use ResourceOwnerPasswordAccessTokenProvider.refreshAccessToken but
        // calls ResourceOwnerPasswordAccessTokenProvider.obtainAccessToken
        //
        // We'll replace that behaviour:
        // if there's no access token - create new one
        // if access token expired - refresh token

        AccessTokenProvider accessTokenProvider = null;
        try {
            Field privateField = null;
            Class clazz = OAuth2RestTemplate.class;
            privateField = OAuth2RestTemplate.class.getDeclaredField("accessTokenProvider");
            privateField.setAccessible(true);
            accessTokenProvider = (AccessTokenProvider) privateField.get(this);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }

        AccessTokenRequest accessTokenRequest = oauth2Context.getAccessTokenRequest();
        if (accessTokenRequest == null) {
            throw new AccessTokenRequiredException(
                    "No OAuth 2 security context has been established. Unable to access resource '"
                            + this.getResource().getId() + "'.", getResource());
        }

        // Transfer the preserved state from the (longer lived) context to the current request.
        String stateKey = accessTokenRequest.getStateKey();
        if (stateKey != null) {
            accessTokenRequest.setPreservedState(oauth2Context.removePreservedState(stateKey));
        }

        OAuth2AccessToken existingToken = oauth2Context.getAccessToken();
        if (existingToken != null) {
            accessTokenRequest.setExistingToken(existingToken);
        }

        OAuth2AccessToken accessToken = null;
        if (null == existingToken)
            accessToken = accessTokenProvider.obtainAccessToken(getResource(), accessTokenRequest);
        else
            accessToken = accessTokenProvider.refreshAccessToken(getResource(), existingToken.getRefreshToken(), accessTokenRequest);

        if (accessToken == null || accessToken.getValue() == null) {
            throw new IllegalStateException(
                    "Access token provider returned a null access token, which is illegal according to the contract.");
        }
        oauth2Context.setAccessToken(accessToken);
        return accessToken;
    }
}
