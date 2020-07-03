package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonPolicyVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettingsVerifier;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Defaults;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.AstAdminSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service.TestService;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import jetbrains.buildServer.controllers.ActionErrors;
import jetbrains.buildServer.controllers.BasePropertiesBean;
import jetbrains.buildServer.controllers.StatefulObject;
import jetbrains.buildServer.controllers.admin.projects.BuildTypeForm;
import jetbrains.buildServer.controllers.admin.projects.EditRunTypeControllerExtension;
import jetbrains.buildServer.serverSide.BuildTypeSettings;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.util.StringUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Messages.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;

/**
 * PT AI build step configuration page requires access to some globally defined
 * serrings. This class publishes these settings using fillModel method
 */
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
        // Setup possibly missing fields
        if (!SERVER_SETTINGS_GLOBAL.equals(properties.get(SERVER_SETTINGS)) && !SERVER_SETTINGS_LOCAL.equals(properties.get(SERVER_SETTINGS)))
            properties.put(SERVER_SETTINGS, Defaults.SERVER_SETTINGS);
        if (!AST_SETTINGS_UI.equals(properties.get(AST_SETTINGS)) && !AST_SETTINGS_JSON.equals(properties.get(AST_SETTINGS)))
            properties.put(AST_SETTINGS, Defaults.AST_SETTINGS);
        if (!properties.containsKey(FAIL_IF_FAILED))
            properties.put(FAIL_IF_FAILED, Defaults.FAIL_IF_FAILED);
        if (!properties.containsKey(FAIL_IF_UNSTABLE))
            properties.put(FAIL_IF_UNSTABLE, Defaults.FAIL_IF_UNSTABLE);
        if (!properties.containsKey(VERBOSE))
            properties.put(VERBOSE, Defaults.VERBOSE);
        if (!properties.containsKey(FLATTEN))
            properties.put(FLATTEN, Defaults.FLATTEN);
        if (!properties.containsKey(REMOVE_PREFIX))
            properties.put(REMOVE_PREFIX, Defaults.REMOVE_PREFIX);
        // Additional settings are to be defined as a model
        model.put(URL, settings.getValue(URL));
        model.put(USER, settings.getValue(USER));
        // We don't need publicKey property in the model as TeamCity did that for us
    }

    @Override
    public void updateState(@NotNull HttpServletRequest request, @NotNull BuildTypeForm form) {}

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
        BasePropertiesBean bean = form.getBuildRunnerBean().getPropertiesBean();
        final Map<String, String> properties = bean.getProperties();
        ActionErrors res = new ActionErrors();
        // Check if connection settings are valid
        BasePropertiesBean settingsBean;
        if (SERVER_SETTINGS_GLOBAL.equalsIgnoreCase(properties.get(SERVER_SETTINGS))) {
            // Let's check global connection settings using existing validator
            settingsBean = new BasePropertiesBean(null);
            settings.getProperties().forEach(
                    (k, v) -> settingsBean.setProperty(k.toString(), (null == v) ? null : v.toString()));
            ActionErrors globalSettingsErrors = TestService.validateConnectionSettings(settingsBean);
            if (globalSettingsErrors.hasErrors())
                // There may be several errors exist, but we should show only a generic message
                res.addError(SERVER_SETTINGS, MESSAGE_GLOBAL_SETTINGS_INVALID);
        } else {
            res.addAll(TestService.validateConnectionSettings(bean));
        }

        res.addAll(TestService.validateScanSettings(bean));

        if (StringUtil.isEmptyOrSpaces(properties.get(INCLUDES)))
            res.addError(INCLUDES, MESSAGE_INCLUDES_EMPTY);
        if (StringUtil.isEmptyOrSpaces(properties.get(PATTERN_SEPARATOR)))
            res.addError(PATTERN_SEPARATOR, MESSAGE_PATTERN_SEPARATOR_EMPTY);
        else {
            try {
                Pattern.compile(properties.get(PATTERN_SEPARATOR));
            } catch (PatternSyntaxException e) {
                res.addError(PATTERN_SEPARATOR, MESSAGE_PATTERN_SEPARATOR_INVALID);
            }
        }
        return res;
    }

    @Override
    public void updateBuildType(
            @NotNull HttpServletRequest request, @NotNull BuildTypeForm form,
            @NotNull BuildTypeSettings buildTypeSettings, @NotNull ActionErrors errors) {}
}
