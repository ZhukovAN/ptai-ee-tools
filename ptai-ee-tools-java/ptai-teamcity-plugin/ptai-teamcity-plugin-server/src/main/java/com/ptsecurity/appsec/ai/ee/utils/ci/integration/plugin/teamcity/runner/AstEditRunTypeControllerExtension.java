package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.AstAdminSettings;
import jetbrains.buildServer.controllers.ActionErrors;
import jetbrains.buildServer.controllers.StatefulObject;
import jetbrains.buildServer.controllers.admin.projects.BuildTypeForm;
import jetbrains.buildServer.controllers.admin.projects.EditRunTypeControllerExtension;
import jetbrains.buildServer.serverSide.BuildTypeSettings;
import jetbrains.buildServer.serverSide.SBuildServer;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

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

    @Override
    public void fillModel(@NotNull HttpServletRequest request, @NotNull BuildTypeForm form, @NotNull Map model) {
        // Additional settings may me defined as a propertiesBean
        final Map<String, String> properties = form.getBuildRunnerBean().getPropertiesBean().getProperties();
        properties.put(GLOBAL_URL, settings.getValue(GLOBAL_URL));
        properties.put(GLOBAL_USER, settings.getValue(GLOBAL_USER));
        properties.put(GLOBAL_TOKEN, settings.getValue(GLOBAL_TOKEN));
        properties.put(GLOBAL_TRUSTED_CERTIFICATES, settings.getValue(GLOBAL_TRUSTED_CERTIFICATES));
        // ... or as a model property (JFYI, not used)
        // model.put(GLOBAL_URL, settings.getValue(GLOBAL_URL));
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
