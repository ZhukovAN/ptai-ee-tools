package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Defaults;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.AstAdminSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service.AstSettingsService;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service.PropertiesBean;
import jetbrains.buildServer.controllers.ActionErrors;
import jetbrains.buildServer.controllers.BasePropertiesBean;
import jetbrains.buildServer.controllers.StatefulObject;
import jetbrains.buildServer.controllers.admin.projects.BuildTypeForm;
import jetbrains.buildServer.controllers.admin.projects.EditRunTypeControllerExtension;
import jetbrains.buildServer.serverSide.BuildTypeSettings;
import jetbrains.buildServer.serverSide.SBuildServer;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;

/**
 * PT AI build step configuration page requires access to some globally defined
 * serrings. This class publishes these settings using fillModel method
 */
@Slf4j
public class AstEditRunTypeControllerExtension implements EditRunTypeControllerExtension {
    private final AstAdminSettings settings;

    public AstEditRunTypeControllerExtension(@NotNull final SBuildServer server,
                                            @NotNull final AstAdminSettings settings) {
        server.registerExtension(EditRunTypeControllerExtension.class, Constants.RUNNER_TYPE, this);
        this.settings = settings;
    }

    /**
     * Fills model with build step attribute values. We also need to pay special attention
     * to missing fields: as TeamCity uses AstRunType.getDefaultRunnerProperties
     * to get default field vaules, initially propertiesBean doesn't contain fields
     * whose values are equal to default ones and default values are set to empty or false,
     * for example, for FAIL_IF_UNSTABLE, REMOVE_PREFIX and FLATTEN fields
     * The result is that corresponding fields are marked as modified in the UI.
     * For example, props:checkboxProperty marks field with valueChanged class if
     * propertiesBean's field value doesn't equal to its default value and if we won't
     * explicitly set missing bean field comparision will look like
     * null != [default.value] and, evidently, field with default value will
     * be marked as changed
     * @param request
     * @param form
     * @param model
     */
    @Override
    public void fillModel(@NotNull HttpServletRequest request, @NotNull BuildTypeForm form, @NotNull Map model) {
        BasePropertiesBean bean = form.getBuildRunnerBean().getPropertiesBean();
        final Map<String, String> properties = bean.getProperties();
        // Setup possibly missing fields: Teamcity doesn't save empty or false values to job's
        // XML file. So when UI opens settings page it compares default values with those
        // missing ones and marks them as orange "modified" fields. So we need to explicitly
        // pass empty or false field values
        if (!SERVER_SETTINGS_GLOBAL.equals(properties.get(SERVER_SETTINGS)) && !SERVER_SETTINGS_LOCAL.equals(properties.get(SERVER_SETTINGS)))
            properties.put(SERVER_SETTINGS, Defaults.SERVER_SETTINGS);
        if (!AST_SETTINGS_UI.equals(properties.get(AST_SETTINGS)) && !AST_SETTINGS_JSON.equals(properties.get(AST_SETTINGS)))
            properties.put(AST_SETTINGS, Defaults.AST_SETTINGS);
        if (!REPORT_SETTINGS_NONE.equals(properties.get(REPORT_SETTINGS)) && !REPORT_SETTINGS_SINGLE.equals(properties.get(REPORT_SETTINGS)) && !REPORT_SETTINGS_JSON.equals(properties.get(REPORT_SETTINGS)))
            properties.put(REPORT_SETTINGS, Defaults.REPORT_SETTINGS);

        if (!properties.containsKey(FAIL_IF_FAILED))
            properties.put(FAIL_IF_FAILED, FALSE);
        if (!properties.containsKey(FAIL_IF_UNSTABLE))
            properties.put(FAIL_IF_UNSTABLE, FALSE);
        if (!properties.containsKey(VERBOSE))
            properties.put(VERBOSE, FALSE);
        if (!properties.containsKey(USE_DEFAULT_EXCLUDES))
            properties.put(USE_DEFAULT_EXCLUDES, FALSE);
        if (!properties.containsKey(FLATTEN))
            properties.put(FLATTEN, FALSE);
        if (!properties.containsKey(REMOVE_PREFIX))
            properties.put(REMOVE_PREFIX, "");
        // Additional settings are to be defined as a model
        model.put(URL, settings.getValue(URL));
        // We don't need publicKey property in the model as TeamCity did that for us
    }

    @Override
    public void updateState(@NotNull HttpServletRequest request, @NotNull BuildTypeForm form) {
        log.trace("Update state request to %s", request.getRequestURI());
    }

    @Nullable
    @Override
    public StatefulObject getState(@NotNull HttpServletRequest request, @NotNull BuildTypeForm form) {
        return null;
    }

    /**
     * This method is called by TeamCity server internally and it checks build step parameters
     * before save.
     * @param request
     * @param form
     * @return
     */
    @NotNull
    @Override
    public ActionErrors validate(@NotNull HttpServletRequest request, @NotNull BuildTypeForm form) {
        PropertiesBean bean = new PropertiesBean(form.getBuildRunnerBean().getPropertiesBean());
        AstSettingsService.VerificationResults results = AstSettingsService.checkConnectionSettings(bean, true);
        AstSettingsService.checkAstSettings(bean, results, true);
        ActionErrors errors = new ActionErrors();
        results.stream().filter(r -> null != r.getLeft()).forEach(e -> errors.addError(e.getLeft(), e.getRight()));
        return errors;
    }

    @Override
    public void updateBuildType(
            @NotNull HttpServletRequest request, @NotNull BuildTypeForm form,
            @NotNull BuildTypeSettings buildTypeSettings, @NotNull ActionErrors errors) {
        log.trace("Update build type request to %s", request.getRequestURI());
    }
}
