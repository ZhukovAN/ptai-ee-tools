package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.AstAdminSettings;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.BuildStartContext;
import jetbrains.buildServer.serverSide.BuildStartContextProcessor;
import org.jetbrains.annotations.NotNull;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;

/**
 * Globally defined (in the Administration / Integration / PT AI) parameters
 * like PT AI server URL are required to execute AST job. As these parameters
 * aren't part of PT AI build step configuration (as only project name,
 * include/exclude etc. are defined there), we need to add these settings
 * manually using updateParameters method
 */
public class AstBuildStartContextProcessor implements BuildStartContextProcessor {
    private ExtensionHolder extensionHolder;
    private AstAdminSettings settings;

    public AstBuildStartContextProcessor(@NotNull final ExtensionHolder extensionHolder, AstAdminSettings settings) {
        this.extensionHolder = extensionHolder;
        this.settings = settings;
    }

    /**
     * Adds globally defined parameter values to agent job as these parameters aren't
     * part of build step configuration
     * @param context
     */
    @Override
    public void updateParameters(@NotNull BuildStartContext context) {
        context.addSharedParameter(GLOBAL_URL, settings.getValue(GLOBAL_URL));
        context.addSharedParameter(GLOBAL_USER, settings.getValue(GLOBAL_USER));
        context.addSharedParameter(GLOBAL_TOKEN, settings.getValue(GLOBAL_TOKEN));
        context.addSharedParameter(GLOBAL_TRUSTED_CERTIFICATES, settings.getValue(GLOBAL_TRUSTED_CERTIFICATES));
    }

    public void register() {
        extensionHolder.registerExtension(BuildStartContextProcessor.class, this.getClass().getName(), this);
    }
}
