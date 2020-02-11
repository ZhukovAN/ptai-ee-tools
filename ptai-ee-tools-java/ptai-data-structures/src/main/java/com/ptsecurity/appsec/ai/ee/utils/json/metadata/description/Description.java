package com.ptsecurity.appsec.ai.ee.utils.json.metadata.description;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

import static com.ptsecurity.appsec.ai.ee.utils.json.metadata.description.LocalizedDescription.*;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class Description {
    @JsonProperty("Key")
    protected String key;
    @JsonProperty("IssueType")
    protected Integer issueType;
    @JsonProperty("Values")
    protected Map<String, LocalizedDescription> values;

    public static final Description DEFAULT = new Description(
            "", new Integer(-1), new HashMap<String, LocalizedDescription>() {{
        put(RU, new LocalizedDescription("", "", ""));
        put(EN, new LocalizedDescription("", "", ""));
        put(KO, new LocalizedDescription("", "", ""));
    }}
    );
}
