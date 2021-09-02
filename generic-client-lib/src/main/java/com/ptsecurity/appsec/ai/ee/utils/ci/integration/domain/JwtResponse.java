package com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class JwtResponse {
    @JsonProperty("accessToken")
    protected String accessToken;

    @JsonProperty("refreshToken")
    protected String refreshToken;

    // As we do need to track expiration date (instead, JwtAuthenticator processes response code)
    // we may use raw string representation
    @JsonProperty("expiredAt")
    protected String expiredAt;
}
