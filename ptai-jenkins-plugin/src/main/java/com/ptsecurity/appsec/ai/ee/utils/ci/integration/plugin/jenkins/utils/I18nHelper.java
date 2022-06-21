package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.VulnerabilityIssue;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import lombok.NonNull;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Need to map enum values like {@link BaseIssue.Level}
 * to localized string names. As those strings are to be localized, there's no way to map enum value to string value: these
 * values are to be calculated in runtime. So we need to map enum values to {@link java.util.function.Supplier} lambda
 */
public class I18nHelper {
    public static final Map<BaseIssue.Level, Supplier<String>> LEVEL_SUPPLIER_MAP = new HashMap<>();
    public static final Map<BaseIssue.Type, Supplier<String>> TYPE_SUPPLIER_MAP = new HashMap<>();
    public static final Map<BaseIssue.ApprovalState, Supplier<String>> APPROVAL_STATE_SUPPLIER_MAP = new HashMap<>();
    public static final Map<Boolean, Supplier<String>> SUSPECTED_STATE_SUPPLIER_MAP = new HashMap<>();
    public static final Map<VulnerabilityIssue.ScanMode, Supplier<String>> SCAN_MODE_SUPPLIER_MAP = new HashMap<>();
    public static final Map<Stage, Supplier<String>> STAGE_SUPPLIER_MAP = new HashMap<>();

    static {
        LEVEL_SUPPLIER_MAP.put(BaseIssue.Level.HIGH, Resources::i18n_misc_enums_vulnerability_severity_high);
        LEVEL_SUPPLIER_MAP.put(BaseIssue.Level.MEDIUM, Resources::i18n_misc_enums_vulnerability_severity_medium);
        LEVEL_SUPPLIER_MAP.put(BaseIssue.Level.LOW, Resources::i18n_misc_enums_vulnerability_severity_low);
        LEVEL_SUPPLIER_MAP.put(BaseIssue.Level.POTENTIAL, Resources::i18n_misc_enums_vulnerability_severity_potential);
        LEVEL_SUPPLIER_MAP.put(BaseIssue.Level.NONE, Resources::i18n_misc_enums_vulnerability_severity_none);

        TYPE_SUPPLIER_MAP.put(BaseIssue.Type.BLACKBOX, Resources::i18n_misc_enums_vulnerability_clazz_blackbox);
        TYPE_SUPPLIER_MAP.put(BaseIssue.Type.CONFIGURATION, Resources::i18n_misc_enums_vulnerability_clazz_configuration);
        TYPE_SUPPLIER_MAP.put(BaseIssue.Type.SCA, Resources::i18n_misc_enums_vulnerability_clazz_sca);
        TYPE_SUPPLIER_MAP.put(BaseIssue.Type.UNKNOWN, Resources::i18n_misc_enums_vulnerability_clazz_unknown);
        TYPE_SUPPLIER_MAP.put(BaseIssue.Type.VULNERABILITY, Resources::i18n_misc_enums_vulnerability_clazz_vulnerability);
        TYPE_SUPPLIER_MAP.put(BaseIssue.Type.WEAKNESS, Resources::i18n_misc_enums_vulnerability_clazz_weakness);
        TYPE_SUPPLIER_MAP.put(BaseIssue.Type.YARAMATCH, Resources::i18n_misc_enums_vulnerability_clazz_yaramatch);

        APPROVAL_STATE_SUPPLIER_MAP.put(BaseIssue.ApprovalState.APPROVAL, Resources::i18n_misc_enums_vulnerability_approval_confirmed);
        APPROVAL_STATE_SUPPLIER_MAP.put(BaseIssue.ApprovalState.AUTO_APPROVAL, Resources::i18n_misc_enums_vulnerability_approval_auto);
        APPROVAL_STATE_SUPPLIER_MAP.put(BaseIssue.ApprovalState.DISCARD, Resources::i18n_misc_enums_vulnerability_approval_rejected);
        APPROVAL_STATE_SUPPLIER_MAP.put(BaseIssue.ApprovalState.NONE, Resources::i18n_misc_enums_vulnerability_approval_none);
        APPROVAL_STATE_SUPPLIER_MAP.put(BaseIssue.ApprovalState.NOT_EXIST, Resources::i18n_misc_enums_vulnerability_approval_missing);

        SUSPECTED_STATE_SUPPLIER_MAP.put(Boolean.TRUE, Resources::i18n_misc_enums_vulnerability_suspected_true);
        SUSPECTED_STATE_SUPPLIER_MAP.put(Boolean.FALSE, Resources::i18n_misc_enums_vulnerability_suspected_false);

        SCAN_MODE_SUPPLIER_MAP.put(VulnerabilityIssue.ScanMode.FROM_ENTRYPOINT, Resources::i18n_misc_enums_vulnerability_scanmode_entrypoint);
        SCAN_MODE_SUPPLIER_MAP.put(VulnerabilityIssue.ScanMode.FROM_OTHER, Resources::i18n_misc_enums_vulnerability_scanmode_other);
        SCAN_MODE_SUPPLIER_MAP.put(VulnerabilityIssue.ScanMode.FROM_PUBLICPROTECTED, Resources::i18n_misc_enums_vulnerability_scanmode_publicprotected);
        SCAN_MODE_SUPPLIER_MAP.put(VulnerabilityIssue.ScanMode.NONE, Resources::i18n_misc_enums_vulnerability_scanmode_none);

        STAGE_SUPPLIER_MAP.put(Stage.ABORTED, Resources::i18n_misc_enums_progress_stage_aborted);
        STAGE_SUPPLIER_MAP.put(Stage.FAILED, Resources::i18n_misc_enums_progress_stage_failed);
        STAGE_SUPPLIER_MAP.put(Stage.FINALIZE, Resources::i18n_misc_enums_progress_stage_finalize);
        STAGE_SUPPLIER_MAP.put(Stage.VFSSETUP, Resources::i18n_misc_enums_progress_stage_vfssetup);
        STAGE_SUPPLIER_MAP.put(Stage.AUTOCHECK, Resources::i18n_misc_enums_progress_stage_autocheck);
        STAGE_SUPPLIER_MAP.put(Stage.DONE, Resources::i18n_misc_enums_progress_stage_done);
        STAGE_SUPPLIER_MAP.put(Stage.ENQUEUED, Resources::i18n_misc_enums_progress_stage_enqueued);
        STAGE_SUPPLIER_MAP.put(Stage.INITIALIZE, Resources::i18n_misc_enums_progress_stage_initialize);
        STAGE_SUPPLIER_MAP.put(Stage.SCAN, Resources::i18n_misc_enums_progress_stage_scan);
        STAGE_SUPPLIER_MAP.put(Stage.SETUP, Resources::i18n_misc_enums_progress_stage_setup);
        STAGE_SUPPLIER_MAP.put(Stage.PRECHECK, Resources::i18n_misc_enums_progress_stage_precheck);
        STAGE_SUPPLIER_MAP.put(Stage.UNKNOWN, Resources::i18n_misc_enums_progress_stage_unknown);
        STAGE_SUPPLIER_MAP.put(Stage.UPLOAD, Resources::i18n_misc_enums_progress_stage_upload);
        STAGE_SUPPLIER_MAP.put(Stage.ZIP, Resources::i18n_misc_enums_progress_stage_zip);
    }

    public static String i18n(@NonNull final BaseIssue.Level level) {
        return LEVEL_SUPPLIER_MAP.get(level).get();
    }

    public static String i18n(@NonNull final BaseIssue.Type type) {
        return TYPE_SUPPLIER_MAP.get(type).get();
    }

    public static String i18n(@NonNull final BaseIssue.ApprovalState state) {
        return APPROVAL_STATE_SUPPLIER_MAP.get(state).get();
    }

    public static String i18n(final boolean state) {
        return SUSPECTED_STATE_SUPPLIER_MAP.get(state).get();
    }

    public static String i18n(@NonNull final VulnerabilityIssue.ScanMode mode) {
        return SCAN_MODE_SUPPLIER_MAP.get(mode).get();
    }

    public static String i18n(@NonNull final Stage stage) {
        return STAGE_SUPPLIER_MAP.get(stage).get();
    }
}
