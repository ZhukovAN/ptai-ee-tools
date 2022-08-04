package com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
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
