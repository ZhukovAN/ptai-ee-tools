package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.jwt;

import com.ptsecurity.appsec.ai.ee.ptai.server.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.ApiClientHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.BaseClient;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.Authenticator;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Route;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.util.regex.Pattern;

/**
 * Class implements jwt authentication for generic XxxApi instance. As XxxApi classes
 * have no common ancestor we need to pass Object type to constructor and use
 * ApiClientHelper to call methods.
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticator extends Base implements Authenticator {
    private static final Pattern INVALID_TOKEN_ERROR = Pattern.compile(".*\\s*error\\s*=\\s*\"?invalid_token\"?.*");
    private static final Pattern UNAUTHORIZED_ERROR = Pattern.compile(".*\\s*error\\s*=\\s*\"?unauthorized\"?.*");

    @NonNull
    protected final BaseClient client;

    @NonNull
    protected final ApiClientHelper helper;

    // private boolean fetchingToken = false;

    private final Object mutex = new Object();

    /**
     * Authenticate failed API request using jwt scheme
     * @param route
     * @param response Response from server
     * @return Modified API request with jwt access token in Authorization header
     * @throws IOException
     */
    @Override
    public Request authenticate(Route route, @NonNull Response response) throws IOException {
        // Any authentication problem while getting jwt treated as a critical failure
        Request res = null;

        synchronized (mutex) {
            do {
                String auth = response.header("WWW-Authenticate");
                if (StringUtils.isEmpty(auth) || !auth.startsWith("Bearer")) {
                    log.error("Unauthorized, but invalid WWW-Authenticate response header");
                    break;
                }
                if (UNAUTHORIZED_ERROR.matcher(auth).find() || INVALID_TOKEN_ERROR.matcher(auth).find() || (null == client.getJwt()))
                    // Need to acquire new / refresh existing jwt using client secret
                    try {
                        client.authenticate();
                    } catch (ApiException e) {
                        // Do not try to call with new jwt as authentication failed
                        severe(e);
                        break;
                    }
                else break;

                // Tell OkHTTP to resend failed request with new jwt
                res = response.request().newBuilder()
                        .header("Authorization", "Bearer " + client.getJwt().getAccessToken())
                        .build();
            } while (false);
        }
        return res;
    }
}
