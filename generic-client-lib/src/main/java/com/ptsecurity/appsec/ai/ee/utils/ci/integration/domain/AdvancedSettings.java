package com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.CallHelper;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static java.lang.Boolean.TRUE;

@Slf4j
public class AdvancedSettings implements Serializable {
    protected static final String SYSTEM_PREFIX = "ptai.";
    private static AdvancedSettings DEFAULT;

    private final Map<SettingInfo, Object> settings = new HashMap<>();

    public enum SettingType {
        STRING, INTEGER, BOOLEAN, ENUM
    }

    public enum PluginType {
        CLI, JENKINS, TEAMCITY;
        public static Set<PluginType> ALL = new HashSet<>(Arrays.asList(CLI, JENKINS, TEAMCITY));
    }

    @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
    @Getter
    public enum SettingInfo {
        AST_FILECOLLECT_IGNORE_CHARSET(
                "ast.filecollect.ignore.charset",
                SettingType.STRING, "",
                Resources::i18n_ast_settings_advanced_ast_file_collect_ignore_invalid_charset,
                PluginType.ALL, SettingInfo::parseBoolean),
        AST_JOB_POLL_INTERVAL(
                "ast.job.poll.interval",
                SettingType.INTEGER, 15,
                Resources::i18n_ast_settings_advanced_ast_job_poll_interval,
                PluginType.ALL, SettingInfo::parseInteger),
        AST_PROJECT_SCAN_ALREADY_SCHEDULED_PROCESSING(
                "ast.project.scan.alreadyscheduled.processing",
                SettingType.ENUM, ScanAlreadyScheduledProcessingResult.ERROR,
                Resources::i18n_ast_settings_advanced_ast_project_setup_failed_custommessage,
                PluginType.ALL, ScanAlreadyScheduledProcessingResult::valueOf),
        AST_PROJECT_SETUP_FAILED_CUSTOMMESSAGE(
                "ast.project.setup.failed.custommessage",
                SettingType.STRING, "",
                Resources::i18n_ast_settings_advanced_ast_project_setup_failed_custommessage,
                PluginType.ALL, (s) -> s),
        AST_RESULT_REST_URL_FILENAME(
                "ast.result.rest.url.filename",
                SettingType.STRING, "",
                Resources::i18n_ast_settings_advanced_ast_result_rest_url_filename,
                PluginType.ALL, (s) -> s),
        HTTP_REQUEST_READ_TIMEOUT(
                "http.request.read.timeout",
                SettingType.INTEGER, 3600,
                Resources::i18n_ast_settings_advanced_http_request_read_timeout,
                PluginType.ALL, SettingInfo::parseInteger),
        HTTP_REQUEST_WRITE_TIMEOUT(
                "http.request.write.timeout",
                SettingType.INTEGER, 3600,
                Resources::i18n_ast_settings_advanced_http_request_write_timeout,
                PluginType.ALL, SettingInfo::parseInteger),
        JENKINS_DATA_CHUNK_SIZE(
                "jenkins.data.chunk.size",
                SettingType.INTEGER, 10 * 1024 * 1024,
                Resources::i18n_ast_settings_advanced_jenkins_data_chunk_size,
                Collections.singleton(PluginType.JENKINS), SettingInfo::parseInteger),
        LOGGING_HTTP_CREDENTIALS(
                "logging.http.credentials",
                SettingType.BOOLEAN, Boolean.FALSE,
                Resources::i18n_ast_settings_advanced_logging_http_credentials,
                PluginType.ALL, SettingInfo::parseBoolean),

        LOGGING_HTTP_REQUEST_MAX_BODY_SIZE(
                "logging.http.request.max.body.size",
                SettingType.INTEGER, 51200,
                Resources::i18n_ast_settings_advanced_logging_http_request_max_body_size,
                PluginType.ALL, SettingInfo::parseInteger),
        /**
         * Maximum response body size to be output to log
         */
        LOGGING_HTTP_RESPONSE_MAX_BODY_SIZE(
                "logging.http.response.max.body.size",
                SettingType.INTEGER, 102400,
                Resources::i18n_ast_settings_advanced_logging_http_response_max_body_size,
                PluginType.ALL, SettingInfo::parseInteger);

        public enum ScanAlreadyScheduledProcessingResult {
            ERROR, WARNING, INFO
        }

        private final String name;
        private final SettingType type;
        private final Object defaultValue;
        private final Supplier<String> descriptionFunction;
        private final Set<PluginType> pluginTypes;

        @Getter
        private final Function<String, Object> parser;

        private static Object parseBoolean(@NonNull final String value) {
            return TRUE.toString().equalsIgnoreCase(value);
        }

        private static Object parseInteger(@NonNull final String value) throws GenericException {
            return CallHelper.call(() -> Integer.parseInt(value), "Integer setting parse failed");
        }
    }

    public static AdvancedSettings getDefault() {
        if (null == DEFAULT) DEFAULT = new AdvancedSettings();
        return DEFAULT;
    }

    public AdvancedSettings() {
        for (SettingInfo settingInfo : SettingInfo.values())
            settings.put(settingInfo, settingInfo.getDefaultValue());
        apply();
    }

    public void apply(@NonNull final Properties properties, final boolean systemProperties) {
        for (SettingInfo setting : SettingInfo.values()) {
            String settingName = setting.getName();
            if (systemProperties) settingName = SYSTEM_PREFIX + settingName;
            String stringValue = properties.getProperty(settingName);
            if (null == stringValue) continue;
            try {
                Object value = setting.getParser().apply(stringValue);
                log.trace("Set {} = {}", setting.getName(), value);
                settings.put(setting, value);
            } catch (GenericException e) {
                log.warn("Skip {} = {} as conversion failed", setting.getName(), stringValue);
            }
        }
    }

    public void apply() {
        log.trace("Set advanced settings values using system properties");
        apply(System.getProperties(), true);
    }

    @SneakyThrows
    public void apply(final String settings) {
        if (StringUtils.isEmpty(settings)) return;
        Properties properties = new Properties();
        ByteArrayInputStream bis = new ByteArrayInputStream(settings.getBytes(StandardCharsets.UTF_8));
        properties.load(bis);
        apply(properties, false);
    }

    public static void validate(final String settings) throws GenericException {
        ByteArrayInputStream bis = new ByteArrayInputStream(settings.getBytes(StandardCharsets.UTF_8));
        CallHelper.call(() -> new Properties().load(bis), "Properties load failed");
    }

    public int getInt(@NonNull final SettingInfo info) {
        if (SettingType.INTEGER != info.getType())
            throw GenericException.raise("Can't get advanced setting integer value", new ClassCastException());
        return (Integer) settings.get(info);
    }

    public String getString(@NonNull final SettingInfo info) {
        if (SettingType.STRING != info.getType())
            throw GenericException.raise("Can't get advanced setting string value", new ClassCastException());
        return (String) settings.get(info);
    }

    public boolean getBoolean(@NonNull final SettingInfo info) {
        if (SettingType.BOOLEAN != info.getType())
            throw GenericException.raise("Can't get advanced setting boolean value", new ClassCastException());
        return (Boolean) settings.get(info);
    }

    @Override
    public String toString() {
        List<String> result = new ArrayList<>();
        for (SettingInfo setting : SettingInfo.values()) {
            result.add("# " + setting.descriptionFunction.get());
            result.add(setting.getName() + " = " + settings.get(setting));
        }
        return result.stream().collect(Collectors.joining(System.getProperty("line.separator")));
    }
}
