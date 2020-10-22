package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.java.Log;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Security;
import java.util.Map;
import java.util.logging.Level;

@Slf4j
public class Base {
    public static final String DEFAULT_SAST_FOLDER = ".ptai";
    public static final String DEFAULT_PTAI_NODE_NAME = "ptai";
    public static final String DEFAULT_PTAI_URL = "https://ptai.domain.org:443";
    public static final String DEFAULT_PREFIX = "[PT AI] ";

    @Setter
    protected boolean verbose = false;

    @Setter
    @Getter
    protected PrintStream console = null;

    @Setter
    @Getter
    @NonNull
    protected String prefix = DEFAULT_PREFIX;

    protected void out(final String value) {
        if (null == value) return;
        if (null != console) console.println(prefix + value);
    }

    protected void out(final Throwable t) {
        if (null == t) return;
        if (null != console) t.printStackTrace(console);
    }

    protected void exception(@NonNull final String message, @NonNull final Exception e, @NonNull final boolean critical) {
        Exception cause = e;
        String details = null;
        if (e instanceof ApiException) {
            ApiException apiException = (ApiException) e;
            cause = apiException.getInner();
            details = apiException.getDetails();
        }
        if (critical) {
            log.error(message, cause);
            if (StringUtils.isNotEmpty(details)) log.error(details);
        } else {
            log.warn(message, cause);
            if (StringUtils.isNotEmpty(details)) log.warn(details);
        }


        if (null == console) return;

        out(message);
        if (verbose)
            // No need to output exception message to console as it will
            // be printed as part of printStackTrace call
            out(cause);
        else
            out(cause.getMessage());
        out(details);
    }

    public void info(final String value) {
        log.info(value);
        out(value);
    }

    public void info(@NonNull final String format, final Object ... values) {
        info(String.format(format, values));
    }

    public void warning(final String value) {
        log.warn(value);
        out(value);
    }

    public void warning(@NonNull final String message, @NonNull final Exception e) {
        exception(message, e, false);
    }

    public void severe(@NonNull final String value) {
        log.error(value);
        out(value);
    }

    public void severe(@NonNull final String message, @NonNull final Exception e) {
        exception(message, e, true);
    }

    public void fine(@NonNull final String value) {
        log.debug(value);
        if (verbose) out(value);
    }

    public void fine(@NonNull final String format, final Object ... values) {
        fine(String.format(format, values));
    }

}
