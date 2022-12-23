package com.ptsecurity.misc.tools.exceptions;

import lombok.Getter;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.impl.EnglishReasonPhraseCatalog;

import java.io.PrintStream;

import static org.joor.Reflect.on;

/**
 * As OpenAPI generator creates individual ApiException classes
 * for every YAML definition file, we need a simple way to "generalize"
 * them. ApiException checks root cause exception for its class
 * and encapsulates exception data. Field {@link GenericException#getDetailedMessage()} of this exception
 * should be human-understandable reason for this exception, like
 * "PT AI license information read failed" etc.
 */
public class GenericException extends RuntimeException {
    /**
     * Some exception types, especially ApiException, may hide interesting details like responseBody.
     * We'll put that data here
     */
    @Getter
    protected String details;

    /**
     * Regular expression pattern to check if root exception is an instance
     * of ApiException
     */
    private static final String APIEXCEPTION_CLASS_REGEX = "com\\.ptsecurity\\.appsec\\.ai\\.ee\\.ptai\\.server\\.[\\w.]+\\.[\\w.]+\\.ApiException";

    /**
     * Method checks if exception is not an instance of ApiException
     * @param e Exception to be checked
     * @return True if exception is not an instance of ApiException
     */
    private static boolean isNotApi(@NonNull Throwable e) {
        Class<? extends @NonNull Throwable> clazz = e.getClass();
        return !clazz.getCanonicalName().matches(APIEXCEPTION_CLASS_REGEX);
    }

    @NonNull
    public static GenericException raise(@NonNull final String caption, @NonNull final Throwable cause) {
        // If inner exception is ApiException or its descendants itself, than there's no need
        // to encapsulate it one more time, just return it
        if (cause instanceof GenericException)
            return (GenericException) cause;
        return new GenericException(caption, extractDetails(cause), cause);
    }

    protected GenericException(@NonNull final String message, final String details, @NonNull final Throwable inner) {
        // Let's check if inner is an instance of BaseException itself
        super(message);
        this.details = details;
        this.initCause(inner);
    }

    protected static String getCode(@NonNull final Throwable e) {
        if (isNotApi(e)) return null;
        int code = on(e).call("getCode").get();
        if (0 != code) {
            String reason = EnglishReasonPhraseCatalog.INSTANCE.getReason(code, null);
            return String.format("%s (%d)", reason, code);
        } else
            return null;
    }

    private static String extractDetails(@NonNull Throwable e) {
        if (isNotApi(e)) return null;
        // As API exception may be thrown due to client-side issues like
        // lack of certificate in local trust store or JSON parse error,
        // we need to check both detailMessage and response body
        String body = on(e).call("getResponseBody").get();
        if (StringUtils.isNotEmpty(body))
            return "Response body: " + body;
        return null;
    }

    @Override
    public void printStackTrace(PrintStream s) {
        if (null != getCause())
            getCause().printStackTrace(s);
        else
            super.printStackTrace(s);
    }

    /**
     * @return Detailed info about exception. This info contains custom
     * top level reason description like "Report settings validation fail"
     * concatenated with inner exception message and additional exception
     * details extracted from inner exception data
     */
    public String getDetailedMessage() {
        StringBuilder builder = new StringBuilder(getMessage());
        if (StringUtils.isNotEmpty(getCause().getMessage()))
            builder.append(". ").append(getCause().getMessage());
        if (StringUtils.isNotEmpty(details))
            builder.append(". ").append(details);
        return builder.toString();
    }
}
