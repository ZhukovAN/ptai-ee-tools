package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.service;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.ReportsHelper;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.admin.AstAdminSettings;
import jetbrains.buildServer.controllers.BasePropertiesBean;
import jetbrains.buildServer.serverSide.crypt.RSACipher;
import jetbrains.buildServer.util.StringUtil;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.SERVER_SETTINGS_GLOBAL;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.TRUE;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.SERVER_SETTINGS;

public class PropertiesBean extends BasePropertiesBean {
    private final static String PROPERTY_PREFIX = "prop:";
    private final static String ENCRYPTED_PROPERTY_PREFIX = "encryptedProp:";

    @NonNull
    public static String getProperty(@NonNull HttpServletRequest request, @NonNull String name) {
        return StringUtil.emptyIfNull(request.getParameter(PROPERTY_PREFIX + name));
    }

    @NonNull
    public static String getEncryptedProperty(@NonNull HttpServletRequest request, @NonNull String name) {
        return StringUtil.emptyIfNull(request.getParameter(ENCRYPTED_PROPERTY_PREFIX + name));
    }

    public PropertiesBean() {
        super(null);
    }

    public PropertiesBean(@NonNull final BasePropertiesBean bean) {
        super(null);
        for (String key : bean.getProperties().keySet())
            setProperty(key, bean.getProperties().get(key));
    }

    public PropertiesBean fill(@NonNull final String name, @NonNull final HttpServletRequest request) {
        setProperty(name, getProperty(request, name));
        return this;
    }

    public PropertiesBean fillSecret(@NonNull final String name, @NonNull final HttpServletRequest request) {
        setProperty(name, RSACipher.decryptWebRequestData(getEncryptedProperty(request, name)));
        return this;
    }

    public PropertiesBean fill(@NonNull final String name, @NonNull final AstAdminSettings settings) {
        setProperty(name, settings.getValue(name));
        return this;
    }

    public String get(@NonNull final String name) {
        return getProperties().getOrDefault(name, "");
    }

    public boolean empty(@NonNull final String name) {
        return (StringUtils.isEmpty(get(name)));
    }

    public boolean none(@NonNull final String name) {
        return !getProperties().containsKey(name);
    }

    public boolean eq(@NonNull final String name, @NonNull final String value) {
        return value.equals(get(name));
    }

    public boolean isTrue(@NonNull final String name) {
        return TRUE.equals(get(name));
    }

    public boolean injectGlobalSettings(@NonNull final AstAdminSettings settings) {
        if (!eq(SERVER_SETTINGS, SERVER_SETTINGS_GLOBAL)) return false;
        settings.getProperties().forEach(
                (k, v) -> setProperty(k.toString(), (null == v) ? "" : v.toString()));
        return true;
    }

    public Reports convert() throws GenericException {
        return ReportsHelper.convert(getProperties());
    }
}
