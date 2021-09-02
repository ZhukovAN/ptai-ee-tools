package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.AbstractTool;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.api.AbstractApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.Authenticator;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;

/**
 * Class implements jwt authentication for generic XxxApi instance. As XxxApi classes
 * have no common ancestor we need to pass Object type to constructor and use
 * ApiClientHelper to call methods.
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticator extends AbstractTool implements Authenticator {
    private static final String INVALID_TOKEN_ERROR = "\\s*error\\s*=\\s*\"?invalid_token\"?";
    private static final String UNAUTHORIZED_ERROR = "\\s*error\\s*=\\s*\"?unauthorized\"?";

    @NonNull
    protected final AbstractApiClient client;

    /**
     * Mutex that prevents from calling authenticate from multiple threads
     */
    private final Object mutex = new Object();

    /**
     * Authenticate failed API request using JWT scheme
     * @param route
     * @param response Response from server
     * @return Modified API request with JWT access token in Authorization header
     * @throws IOException
     */
    @Override
    public Request authenticate(Route route, @NonNull Response response) throws IOException {
        // Any authentication problem while getting JWT treated as a critical failure
        synchronized (mutex) {
            String auth = response.header("WWW-Authenticate");
            if (StringUtils.isEmpty(auth) || !auth.startsWith("Bearer")) {
                log.error("Unauthorized, but invalid WWW-Authenticate response header");
                return null;
            }
            if (auth.matches(UNAUTHORIZED_ERROR) || auth.matches(INVALID_TOKEN_ERROR) || (null == client.getApiJwt())) {
                // Need to acquire new / refresh existing JWT using client secret
                try {
                    client.authenticate();
                } catch (GenericException e) {
                    // Do not try to call with new JWT as authentication failed
                    severe(e);
                    return null;
                }
            } else
                return null;

            // Tell OkHTTP to resend failed request with new JWT
            return response.request().newBuilder()
                    .header("Authorization", "Bearer " + client.getApiJwt().getAccessToken())
                    .build();
        }
    }
}
