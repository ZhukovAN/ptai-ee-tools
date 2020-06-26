package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Defaults;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.AstAdminSettings;
import jetbrains.buildServer.controllers.ActionErrors;
import jetbrains.buildServer.controllers.BasePropertiesBean;
import jetbrains.buildServer.controllers.StatefulObject;
import jetbrains.buildServer.controllers.admin.projects.BuildTypeForm;
import jetbrains.buildServer.controllers.admin.projects.EditRunTypeControllerExtension;
import jetbrains.buildServer.serverSide.BuildTypeSettings;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.crypt.RSACipher;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.FileCopyUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.lang.reflect.Field;
import java.util.Map;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.*;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;
import static java.nio.charset.StandardCharsets.UTF_8;

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

    @NotNull
    @Override
    public ActionErrors validate(@NotNull HttpServletRequest request, @NotNull BuildTypeForm form) {
        final Map<String, String> properties = form.getBuildRunnerBean().getPropertiesBean().getProperties();
        /*
        String cxPass = properties.get(CxParam.PASSWORD);

        try {
            if(cxPass != null && !EncryptUtil.isScrambled(cxPass)) {
                cxPass = EncryptUtil.scramble(cxPass);
            }
        } catch (RuntimeException e) {
            cxPass = "";
        }
        properties.put(CxParam.PASSWORD, cxPass);
        //the jsp page dosent pass false value, so we need to check if it isnt true, null in this case, set it as false
        //this way we can distinguish in the build process between an old job (sast enabled == null) and a job where user specified not to run sast (sast_enabled == false)
        if(!TRUE.equals(properties.get(CxParam.SAST_ENABLED))) {
            properties.put(CxParam.SAST_ENABLED, CxConstants.FALSE);
        }
        */
        return new ActionErrors();
    }

    @Override
    public void updateBuildType(
            @NotNull HttpServletRequest request, @NotNull BuildTypeForm form,
            @NotNull BuildTypeSettings buildTypeSettings, @NotNull ActionErrors errors) {}
}
