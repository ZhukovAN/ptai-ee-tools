package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.ApiException;
import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.io.PrintStream;
import java.util.concurrent.Callable;

@Slf4j
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@ToString
public class Base {
    public static final String DEFAULT_SAST_FOLDER = ".ptai";
    public static final String DEFAULT_PTAI_NODE_NAME = "ptai";
    public static final String DEFAULT_PTAI_URL = "https://ptai.domain.org:443";
    public static final String DEFAULT_PREFIX = "[PT AI] ";

    @Builder.Default
    protected boolean verbose = false;

    @Builder.Default
    @ToString.Exclude
    protected PrintStream console = null;

    @Builder.Default
    @ToString.Exclude
    protected String prefix = DEFAULT_PREFIX;

    protected void out(final String value) {
        if (null == value) return;
        if (null != console) console.println(null == prefix ? value : prefix + value);
    }

    protected void out(final Throwable t) {
        if (null == t) return;
        if (null != console) t.printStackTrace(console);
    }

    /**
     * Method outputs information about an error or warning. Information saved
     * to log file contains top level root exception cause like "Project search
     * failed", inner exception message and call stack. Also that data is being
     * printed to output stream in accordance with verbosity flag
     * @param e ApiException that contains both top level reason description and root exception cause
     * @param critical If exception to be processed as error or warning
     */
    protected void exception(@NonNull final ApiException e, final boolean critical) {
        Exception cause = e.getInner();
        String details = e.getDetails();
        if (critical) {
            log.error(e.getMessage(), cause);
            if (StringUtils.isNotEmpty(details)) log.error(details);
        } else {
            log.warn(e.getMessage(), cause);
            if (StringUtils.isNotEmpty(details)) log.warn(details);
        }

        out(e.getMessage());
        if (verbose)
            // No need to output inner exception message to console as it will
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

    public void warning(@NonNull final ApiException e) {
        exception(e, false);
    }

    public void severe(@NonNull final String value) {
        log.error(value);
        out(value);
    }

    public void severe(@NonNull final ApiException e) {
        exception(e, true);
    }

    public void fine(@NonNull final String value) {
        log.debug(value);
        if (verbose) out(value);
    }

    public void fine(@NonNull final String format, final Object ... values) {
        fine(String.format(format, values));
    }

    /**
     * Call method that may throw an Exception and wrap that exception into ApiException
     * @param call Function to be called
     * @param errorMessage Generic error message if function call failed
     * @param <V> Function return type
     * @return Finction call result
     * @throws ApiException Exception that wraps internal error and uses errorMessage
     * as error cause description
     */
    public static <V> V callApi(@NonNull Callable<V> call, @NonNull String errorMessage) throws ApiException {
        return callApi(call, errorMessage, false);
    }

    public static <V> V callApi(@NonNull Callable<V> call, @NonNull String errorMessage, final boolean warningOnly) throws ApiException {
        try {
            return call.call();
        } catch (Exception e) {
            if (!warningOnly) throw ApiException.raise(errorMessage, e);
            return null;
        }
    }

    /**
     * Need to implement our own Runnable that throws checked Exception
     */
    @FunctionalInterface
    public interface Runnable {
        void run() throws Exception;
    }

    public static void callApi(@NonNull Runnable call, @NonNull String errorMessage) throws ApiException {
        callApi(call, errorMessage, false);
    }

    public static void callApi(@NonNull Runnable call, @NonNull String errorMessage, final boolean warningOnly) throws ApiException {
        callApi(() -> {
            call.run();
            return null;
        }, errorMessage, warningOnly);
    }
}
