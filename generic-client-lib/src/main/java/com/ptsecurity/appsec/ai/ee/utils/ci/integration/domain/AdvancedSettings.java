package com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.StringHelper.arrayAsString;

@Slf4j
public class AdvancedSettings {
    public static final String HTTP_RESPONSE_MAX_BODY_SIZE = "ptai.http.response.max.body.size";
    protected static final List<String> NAMES = Arrays.asList(HTTP_RESPONSE_MAX_BODY_SIZE);

    static {
        for (String name : NAMES) {
            if (null == System.getProperty(name)) continue;
            log.trace("Set parameter {} = {}", name, System.getProperty(name));
            settings.put(name, System.getProperty(name));
        }
    }

    public final Map<String, String> settings = new HashMap<>();

    public AdvancedSettings() {
        for (String name : NAMES) {
            if (null == System.getProperty(name)) continue;
            log.trace("Set parameter {} = {} as global setting", name, System.getProperty(name));
            settings.put(name, System.getProperty(name));
        }
    }

    public AdvancedSettings(final Properties properties) {
        this();
        if (null == properties) return;
        for (String name : properties.stringPropertyNames()) {
            log.trace("Set (override) parameter {} = {} from properties", name, properties.getProperty(name));
            settings.put(name, System.getProperty(name));
        }
    }

    public int getInt(@NonNull final String name, final int defaultValue) {
        if (!settings.containsKey(name)) {
            log.trace("Parameter {} not found, {} value will be used instead", name, defaultValue);
            return defaultValue;
        }
        try {
            return Integer.parseInt(settings.get(name));
        } catch (NumberFormatException e) {
            log.warn("Bad numeric parameter {} value {}. Default {} will be used instead", name, settings.get(name), defaultValue);
            return defaultValue;
        }
    }

    public String[] getStrings(@NonNull final String name, final String[] defaultValue) {
        if (!settings.containsKey(name)) return defaultValue;
        try {
            String values = settings.get(name);
            return values.split("[, ]+");
        } catch (NumberFormatException e) {
            log.warn("Bad string array parameter {} value {}. Default {} will be used instead", name, settings.get(name), arrayAsString(defaultValue));
            return defaultValue;
        }
    }

    public String getString(@NonNull final String name, final String defaultValue) {
        if (!settings.containsKey(name)) return defaultValue;
        return settings.get(name);
    }
}
