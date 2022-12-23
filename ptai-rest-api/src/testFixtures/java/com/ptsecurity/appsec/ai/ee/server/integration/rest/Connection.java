package com.ptsecurity.appsec.ai.ee.server.integration.rest;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.misc.tools.helpers.ResourcesHelper;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.SneakyThrows;

import java.io.InputStream;
import java.util.Map;

import static com.ptsecurity.misc.tools.helpers.ResourcesHelper.getResourceString;

@Getter
@Setter
@NoArgsConstructor
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class,
        property = "id")
public class Connection {
    protected String id;
    protected ScanBrief.ApiVersion version;
    protected String url;
    protected String token;
    protected String failSafeToken;
    protected String user;
    protected String password;
    protected String ca;
    protected boolean insecure;

    public String getCaPem() {
        return getResourceString(CONNECTION().getCa());
    }

    @Getter
    @Setter
    @NoArgsConstructor
    private static class Configuration {
        protected Map<String, Connection> connections;
        @JsonProperty("current")
        protected Connection current;
    }

    private static Connection CONNECTION = null;

    @SneakyThrows
    public static Connection CONNECTION() {
        if (null == CONNECTION) {
            final InputStream inputStream = ResourcesHelper.getResourceStream("configuration.yml");
            final ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());
            Configuration configuration = objectMapper.readValue(inputStream, Configuration.class);
            CONNECTION = configuration.getCurrent();
        }
        return CONNECTION;
    }
}

