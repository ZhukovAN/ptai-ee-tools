package com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.BaseClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.jwt.JwtResponse;
import lombok.Getter;
import okhttp3.*;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpStatus;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.util.regex.Pattern;

public class JwtAuthenticator extends Base implements Authenticator {
    static final Pattern INVALID_TOKEN_ERROR = Pattern.compile("\\s*error\\s*=\\s*\"?invalid_token\"?");
    static final Pattern UNAUTHORIZED_ERROR = Pattern.compile("\\s*error\\s*=\\s*\"?unauthorized\"?");

    @Getter
    protected JwtResponse jwt = null;

    protected BaseClient.ApiClientHelper clientHelper = null;
    protected String url;
    protected String clientId;
    protected String clientSecret;
    protected String userName;
    protected String password;

    private boolean fetchingToken = false;

    @Nullable
    @Override
    public Request authenticate(@Nullable Route route, @NotNull Response response) throws IOException {

        // Any authentication problem while getting JWT treated as a critical failure
        if (fetchingToken) return null;
        fetchingToken = true;

        Request res = null;
        do {
            String authResponse = response.header("WWW-Authenticate");
            if (StringUtils.isEmpty(authResponse) || !authResponse.startsWith("Bearer")) {
                out("Unauthorized, but invalid WWW-Authenticate response header");
                break;
            }
            RequestBody body = null;
            Response jwtResponse = null;
            if (UNAUTHORIZED_ERROR.matcher(authResponse).find() || (null == jwt)) {
                // Need to acquire new JWT using client id/secret and username/password credentials
                body = new FormBody.Builder()
                        .add("username", userName)
                        .add("password", password)
                        .add("grant_type", "password")
                        .build();
                Request request = response.request().newBuilder()
                        .url(url + "/oauth/token")
                        .post(body)
                        .header("Authorization", Credentials.basic(clientId, clientSecret))
                        .build();
                jwtResponse = clientHelper.getHttpClient().newBuilder().build().newCall(request).execute();
            } else if (INVALID_TOKEN_ERROR.matcher(authResponse).find()) {
                // Need to acquire new JWT using client id/secret and refresh_token
                body = new FormBody.Builder()
                        .add("refresh_token", jwt.getRefreshToken())
                        .add("grant_type", "refresh_token")
                        .build();
                Request request = response.request().newBuilder()
                        .url(url + "/oauth/token")
                        .post(body)
                        .header("Authorization", Credentials.basic(clientId, clientSecret))
                        .build();
                jwtResponse = clientHelper.getHttpClient().newBuilder().build().newCall(request).execute();
                if (HttpStatus.SC_OK != jwtResponse.code()) {
                    // JWT refresh failed. May be refrest token expored, let's re-authenticate using full set of credentials
                    out("JWT refresh failed. Code is {}", jwtResponse.code());
                    jwt = null;
                    body = new FormBody.Builder()
                            .add("username", userName)
                            .add("password", password)
                            .add("grant_type", "password")
                            .build();
                    request = response.request().newBuilder()
                            .url(url + "/oauth/token")
                            .post(body)
                            .header("Authorization", Credentials.basic(clientId, clientSecret))
                            .build();
                    jwtResponse = clientHelper.getHttpClient().newBuilder().build().newCall(request).execute();
                }
            } else break;
            if (HttpStatus.SC_OK != jwtResponse.code()) {
                out("Authorization failed. Code is {}", jwtResponse.code());
                break;
            }
            jwt = new ObjectMapper().readValue(jwtResponse.body().string(), JwtResponse.class);
            clientHelper.setApiKeyPrefix("Bearer");
            clientHelper.setApiKey(jwt.getAccessToken());
            fetchingToken = false;
            res = response.request().newBuilder()
                    // .header("Accept", "application/json")
                    .header("Authorization", "Bearer " + jwt.getAccessToken())
                    .build();
        } while (false);
        fetchingToken = false;
        return res;
    }

    public JwtAuthenticator(Object client, String url, String clientId, String clientSecret, String userName, String password) {
        clientHelper = new BaseClient.ApiClientHelper(client).init();
        this.url = url;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.userName = userName;
        this.password = password;
    }
}
