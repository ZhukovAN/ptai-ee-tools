package com.ptsecurity.appsec.ai.ee.utils.json.metadata.description;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class LocalizedDescription {
    public static final String RU = "1049";
    public static final String EN = "1033";
    public static final String KO = "1042";

    @JsonProperty("Html")
    @Setter
    protected String html;
    @JsonProperty("Header")
    protected String header;
    @JsonProperty("Description")
    protected String description;
}
