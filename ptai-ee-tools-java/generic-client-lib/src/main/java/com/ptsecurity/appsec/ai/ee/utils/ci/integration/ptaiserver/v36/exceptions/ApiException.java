package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.exceptions;

import lombok.Getter;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.impl.EnglishReasonPhraseCatalog;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

import static org.joor.Reflect.on;

/**
 * As OpenAPI generator creates individual ApiException classes
 * for every YAML definition file, we need a simple way to "generalize"
 * them. ApiException checks root cause exception for its class
 * and encapsulates exception data. Field detailMessage of this exception
 * should be human-understandable reason for this exception, like
 * "PT AI license information read failed" etc.
 */
public class ApiException extends PtaiException {
    /**
     * Root cause of this "boxing" exception
     */
    @Getter
    @NonNull
    protected Exception inner;

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
    private static final String APIEXCEPTION_CLASS_REGEX = "com\\.ptsecurity\\.appsec\\.ai\\.ee\\.[\\w\\.]+\\.ApiException";

    /**
     * Method checks if exception is an instance of ApiException
     * @param e
     * @return
     */
    protected static boolean isApi(@NonNull Exception e) {
        Class clazz = e.getClass();
        return clazz.getCanonicalName().matches(APIEXCEPTION_CLASS_REGEX);
    }

    public static ApiException raise(@NonNull final String caption, @NonNull final Exception cause) {
        // If inner exception is ApiException or its descendants itself, than there's no need
        // to encapsulate it one more time, just return it
        if (cause instanceof ApiException)
            return (ApiException) cause;
        return new ApiException(caption, getDetails(cause), cause);
    }

    protected ApiException(@NonNull final String message, final String details, @NonNull final Exception inner) {
        // Let's check if inner is an instance of BaseException itself
        super(message);
        this.details = details;
        this.inner = inner;
    }

    protected static String getCode(@NonNull final Exception e) {
        if (!isApi(e)) return null;
        int code = on(e).call("getCode").get();
        if (0 != code) {
            String reason = EnglishReasonPhraseCatalog.INSTANCE.getReason(code, null);
            return String.format("%s (%d)", reason, code);
        } else
            return null;
    }

    protected static String getDetails(@NonNull Exception e) {
        if (!isApi(e)) return null;
        // As API exception may be thrown due to client-side issues like
        // lack of certificate in local trust store or JSON parse error,
        // we need to check both detailMessage and response body
        String message = e.getMessage();
        int state = 0;
        if (StringUtils.isNotEmpty(message)) state |= (1 << 0);
        String body = on(e).call("getResponseBody").get();
        if (StringUtils.isNotEmpty(body)) state |= (1 << 1);

        if (0 == state)
            return null;
        else if (1 == state)
            return message;
        else if (2 == state)
            return body;
        else
            return body + " (" + message + ")";
    }

    @Override
    public void printStackTrace(PrintStream s) {
        inner.printStackTrace(s);
    }
}
