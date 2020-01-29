package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.jwt;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JwtResponse {
    @JsonProperty("access_token")
    protected String accessToken;
    @JsonProperty("token_type")
    protected String tokenType;
    @JsonProperty("refresh_token")
    protected String refreshToken;
    @JsonProperty("expires_in")
    protected int expiresIn;
    @JsonProperty("scope")
    protected String scope;
    @JsonProperty("jti")
    protected String jti;
}
