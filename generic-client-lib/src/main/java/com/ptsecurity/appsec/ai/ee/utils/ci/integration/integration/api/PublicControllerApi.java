package com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.api;

import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.jwt.JwtResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.utils.JwtAuthenticator;

import java.util.Optional;

public class PublicControllerApi extends com.ptsecurity.appsec.ai.ee.ptai.integration.rest.PublicControllerApi {
    public JwtResponse getCurrentJwt() {
        JwtAuthenticator auth = (JwtAuthenticator) this.getApiClient().getHttpClient().authenticator();
        return Optional.ofNullable(auth)
                .map(JwtAuthenticator::getJwt)
                .orElse(null);
    }

    public PublicControllerApi(ApiClient client) {
        super(client);
    }
}
