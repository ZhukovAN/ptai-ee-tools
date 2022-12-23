package com.ptsecurity.misc.tools;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import java.time.OffsetDateTime;

@Getter
@Setter
@Builder
@ToString
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class Jwt {
    @JsonProperty("accessToken")
    protected String accessToken;

    @JsonProperty("refreshToken")
    protected String refreshToken;

    @JsonProperty("expiredAt")
    protected OffsetDateTime expiredAt;
}
