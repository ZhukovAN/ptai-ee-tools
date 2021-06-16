package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Defaults;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params;
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
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Map;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.AST_MODE;

/**
 * PT AI build step configuration page requires access to some globally defined
 * serrings. This class publishes these settings using fillModel method
 */
@Slf4j
public class AstEditRunTypeControllerExtension implements EditRunTypeControllerExtension {
    private final AstAdminSettings settings;

    public AstEditRunTypeControllerExtension(@NonNull final SBuildServer server,
                                            @NonNull final AstAdminSettings settings) {
        server.registerExtension(EditRunTypeControllerExtension.class, Constants.RUNNER_TYPE, this);
        this.settings = settings;
    }

    /**
     * Fills model with build step attribute values. We also need to pay special attention
     * to missing fields: as TeamCity uses AstRunType.getDefaultRunnerProperties
     * to get default field vaules, initially propertiesBean doesn't contain fields
     * whose values are equal to default ones and default values are set to empty or false,
     * for example, for {@link com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params#FAIL_IF_UNSTABLE},
     * {@link com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params#REMOVE_PREFIX}
     * and {@link com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params#FLATTEN} fields
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
    public void fillModel(@NonNull HttpServletRequest request, @NonNull BuildTypeForm form, @NonNull Map model) {
        BasePropertiesBean bean = form.getBuildRunnerBean().getPropertiesBean();
        final Map<String, String> properties = bean.getProperties();
        // Setup possibly missing fields: Teamcity doesn't save empty or false values to job's
        // XML file. So when UI opens settings page it compares default values with those
        // missing ones and as those are differ marks them as orange "modified" fields. So we need to explicitly
        // pass empty or false field values

        if (!SERVER_SETTINGS_GLOBAL.equals(properties.get(SERVER_SETTINGS)) && !SERVER_SETTINGS_LOCAL.equals(properties.get(SERVER_SETTINGS)))
            properties.put(SERVER_SETTINGS, Defaults.SERVER_SETTINGS);
        if (!AST_SETTINGS_UI.equals(properties.get(AST_SETTINGS)) && !AST_SETTINGS_JSON.equals(properties.get(AST_SETTINGS)))
            properties.put(AST_SETTINGS, Defaults.AST_SETTINGS);
        if (!AST_MODE_ASYNC.equals(properties.get(AST_MODE)) && !AST_MODE_SYNC.equals(properties.get(AST_MODE)))
            properties.put(AST_MODE, Defaults.AST_MODE);

        // I've replaced dummy implementation that checks fields and puts value if there were no desired field
        Arrays.stream(Params.class.getDeclaredFields())
                .filter(f -> Modifier.isPublic(f.getModifiers()))
                .filter(f -> Modifier.isStatic(f.getModifiers()))
                .filter(f -> Modifier.isFinal(f.getModifiers()))
                .map(Field::getName)
                .forEach(n -> {
                    // Skip parameters that are exist in bean
                    if (properties.containsKey(Params.value(n))) return;
                    // If parameter missing, let's fill its value with explicit values: EMPTY or FALSE
                    if (TRUE.equals(Defaults.value(n)) || FALSE.equals((Defaults.value(n))))
                        // Default value for that parameter is TRUE or FALSE, so
                        // it is a boolean parameter and as it is missing, its value is FALSE
                        properties.put(Params.value(n), FALSE);
                    else
                        properties.put(Params.value(n), EMPTY);
                });
        // We don't need publicKey property in the model as TeamCity did that for us

        // Need to explicily call rememberState with newly added attributes
        // as editRunParams.jsp calls BS.EditBuildRunnerForm.setModified(${buildForm.buildRunnerBean.stateModified})
        // BuildRunnerBean's isStateModified calls getPropertiesBean().isStateModified() and as
        // fields data will differ UI will show "The changes are not yet saved" modifiedMessage form
        bean.rememberState();
    }

    @Override
    public void updateState(@NonNull HttpServletRequest request, @NonNull BuildTypeForm form) {
        log.trace("Update state request to %s", request.getRequestURI());
    }

    @Override
    public StatefulObject getState(@NonNull HttpServletRequest request, @NonNull BuildTypeForm form) {
        return null;
    }

    /**
     * This method is called by TeamCity server internally and it checks build step parameters
     * before save.
     * @param request
     * @param form
     * @return
     */
    @NonNull
    @Override
    public ActionErrors validate(@NonNull HttpServletRequest request, @NonNull BuildTypeForm form) {
        PropertiesBean bean = new PropertiesBean(form.getBuildRunnerBean().getPropertiesBean());
        // As we might saving AST job with globally-defined connection settings,
        // we need to inject those settings into bean prior to verification
        bean.injectGlobalSettings(settings);

        AstSettingsService.VerificationResults results = AstSettingsService.checkConnectionSettings(bean, true);
        AstSettingsService.checkAstSettings(bean, results, true);
        ActionErrors errors = new ActionErrors();
        results.stream().filter(r -> null != r.getLeft()).forEach(e -> errors.addError(e.getLeft(), e.getRight()));
        return errors;
    }

    @Override
    public void updateBuildType(
            @NonNull HttpServletRequest request, @NonNull BuildTypeForm form,
            @NonNull BuildTypeSettings buildTypeSettings, @NonNull ActionErrors errors) {
        log.trace("Update build type request to %s", request.getRequestURI());
    }
}
