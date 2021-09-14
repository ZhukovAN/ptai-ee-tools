package com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class AdvancedSettings {
    public static final String HTTP_RESPONSE_MAX_BODY_SIZE = "http.response.max.body.size";
    public static final Map<String, String> SETTINGS = new HashMap<>();

    protected static final List<String> NAMES = Arrays.asList(HTTP_RESPONSE_MAX_BODY_SIZE);

    static {
        for (String name : NAMES) {
            if (null == System.getProperty(name)) continue;
            SETTINGS.put(name, System.getProperty(name));
        }
    }

    public static int getInt(@NonNull final String name, final int defaultValue) {
        if (!SETTINGS.containsKey(name)) return defaultValue;
        try {
            return Integer.parseInt(SETTINGS.get(name));
        } catch (NumberFormatException e) {
            log.warn("Bad numeric parameter {} value {}. Default {} will be used instead", name, SETTINGS.get(name), defaultValue);
            return defaultValue;
        }
    }
}
