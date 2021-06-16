package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.runner;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.AstAdminSettings;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.BuildStartContext;
import jetbrains.buildServer.serverSide.BuildStartContextProcessor;
import lombok.NonNull;

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

    @NonNull
    private AstAdminSettings settings;

    public AstBuildStartContextProcessor(@NonNull final ExtensionHolder extensionHolder, @NonNull AstAdminSettings settings) {
        this.extensionHolder = extensionHolder;
        this.settings = settings;
    }

    /**
     * Adds globally defined parameter values to agent job as these parameters aren't
     * part of build step configuration
     * @param context Agent job context
     */
    @Override
    public void updateParameters(@NonNull BuildStartContext context) {
        context.addSharedParameter(URL, settings.getValue(URL));
        context.addSharedParameter(TOKEN, settings.getValue(TOKEN));
        context.addSharedParameter(CERTIFICATES, settings.getValue(CERTIFICATES));
        context.addSharedParameter(INSECURE, settings.getValue(INSECURE));
    }

    public void register() {
        extensionHolder.registerExtension(BuildStartContextProcessor.class, this.getClass().getName(), this);
    }
}
