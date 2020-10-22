package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import org.apache.commons.validator.routines.UrlValidator;

public class UrlHelper {
    public static boolean checkUrl(final String value) {
        UrlValidator urlValidator = new UrlValidator(
                new String[]{"http", "https"},
                UrlValidator.ALLOW_LOCAL_URLS);
        return urlValidator.isValid(value);
    }

}
