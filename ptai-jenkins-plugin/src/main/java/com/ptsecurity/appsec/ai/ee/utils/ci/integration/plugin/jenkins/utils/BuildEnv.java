package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import hudson.FilePath;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;

import java.io.Serializable;
import java.text.DateFormat;
import java.util.Calendar;
import java.util.Map;
import java.util.TreeMap;

@Slf4j
@NoArgsConstructor
@AllArgsConstructor
public class BuildEnv implements Serializable {
    @Getter
    @Setter
    private TreeMap<String, String> envVars;
    @Getter
    @Setter
    private FilePath baseDirectory;
    @Getter
    @Setter
    private Calendar buildTime;

    public String getNormalizedBaseDirectory() {
        try {
            return baseDirectory.toURI().normalize().getPath();
        } catch (Exception e) {
            throw new RuntimeException("Directory normalization failed", e);
        }
    }

    private String safeGetNormalizedBaseDirectory() {
        if (baseDirectory == null) return null;
        try {
            return getNormalizedBaseDirectory();
        } catch (RuntimeException re) {
            log.debug("Directory normalization failed", re);
            return re.getLocalizedMessage();
        }
    }

    private String safeGetBuildTime() {
        if (buildTime == null) return null;
        try {
            return DateFormat.getDateTimeInstance().format(buildTime.getTime());
        } catch (RuntimeException re) {
            return re.getLocalizedMessage();
        }
    }

    public static final String ENV_JOB_NAME = "JOB_NAME";
    public static final String ENV_BUILD_NUMBER = "BUILD_NUMBER";

    protected ToStringBuilder addToToString(final ToStringBuilder builder) {
        if (envVars != null) {
            builder.append(ENV_JOB_NAME, envVars.get(ENV_JOB_NAME))
                    .append(ENV_BUILD_NUMBER, envVars.get(ENV_BUILD_NUMBER));
        }
        return builder.append("baseDirectory", safeGetNormalizedBaseDirectory())
                .append("buildTime", safeGetBuildTime());
    }

    public String toString() {
        return addToToString(new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)).toString();
    }

    public TreeMap<String, String> getEnvVarsWithPrefix(final String prefix) {
        final TreeMap<String, String> prefixed = new TreeMap<>();
        for (Map.Entry<String, String> entry : envVars.entrySet()) {
            prefixed.put(prefix + entry.getKey(), entry.getValue());
        }
        return prefixed;
    }
}
