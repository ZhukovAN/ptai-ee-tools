package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.UrlValidator;

public class UrlHelper {
    private static final boolean USE_EXTENDED_TLDS = true;
    private static final String[] GENERIC_TLDS_PLUS = new String[] { "corp", "local" };

    public static boolean checkUrl(final String value) {
        UrlValidator urlValidator = new UrlValidator(
                new String[]{"http", "https"},
                UrlValidator.ALLOW_LOCAL_URLS);
        return urlValidator.isValid(value);
    }

    static {
        if (USE_EXTENDED_TLDS)
            DomainValidator.updateTLDOverride(DomainValidator.ArrayType.GENERIC_PLUS, GENERIC_TLDS_PLUS);
    }
}
