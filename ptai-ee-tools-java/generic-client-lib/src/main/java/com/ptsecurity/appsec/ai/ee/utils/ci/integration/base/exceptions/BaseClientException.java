package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.impl.EnglishReasonPhraseCatalog;

import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * As OpenAPI generator creates individual ApiException classes
 * for every YAML definition file, we need a simple way to "generalize"
 * them. BaseClientException checks root cause exception for its class
 * and encapsulates exception data
 */
@NoArgsConstructor
public class BaseClientException extends RuntimeException {
    /**
     * Root cause of this "boxing" exception
     */
    @Getter
    protected Exception inner = null;

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
    protected static boolean check(@NonNull Exception e) {
        Class clazz = e.getClass();
        return !clazz.getCanonicalName().matches(APIEXCEPTION_CLASS_REGEX);
    }

    public BaseClientException(String message, Exception inner) {

        super(message);
        // TODO: Check if inner is inherited from BaseClientException
        this.inner = inner;
    }

    public BaseClientException(String message) {
        this(message, null);
    }

    public static Object getApiExceptionField(@NonNull Exception e, @NonNull String methodName) {
        Class clazz = e.getClass();
        if (!clazz.getCanonicalName().matches(APIEXCEPTION_CLASS_REGEX)) return "";
        try {
            Method method = clazz.getMethod(methodName);
            return method.invoke(e);
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException ex) {
            return null;
        }
    }

    public static String getApiExceptionDetails(@NonNull Exception e) {
        Class clazz = e.getClass();
        if (!clazz.getCanonicalName().matches(APIEXCEPTION_CLASS_REGEX)) return "";

        int code = (int) getApiExceptionField(e, "getCode");
        if (0 != code) {
            String reason = EnglishReasonPhraseCatalog.INSTANCE.getReason(code, null);
            return String.format("%s (%d)", reason, code);
        } else
            return "";
    }

    public static String getApiExceptionMessage(@NonNull Exception e) {
        Class clazz = e.getClass();
        if (!clazz.getCanonicalName().matches(APIEXCEPTION_CLASS_REGEX)) return "";
        // As API exception may be thrown due to client-side issues like
        // lack of certificate in local trust store, we need to check both detailMessage
        // and response body
        String message = e.getMessage();
        int state = 0;
        if (StringUtils.isNotEmpty(message)) state |= (1 << 0);
        String body = (String) getApiExceptionField(e, "getResponseBody");
        if (StringUtils.isNotEmpty(body)) state |= (1 << 1);
        if (0 == state)
            return "";
        else if (1 == state)
            return message;
        else if (2 == state)
            return body;
        else
            return body + " (" + message + ")";
    }

    public static String getInnerExceptionData(Exception exception) {
        return (String) getApiExceptionField(exception, "getResponseBody");
    }

    @Override
    public String getMessage() {
        StringBuilder builder = new StringBuilder();
        List<String> messages = new ArrayList<>();
        do {
            Optional.ofNullable(super.getMessage())
                    .filter(StringUtils::isNotEmpty)
                    .map(messages::add);
            Optional.ofNullable(inner)
                    .map(inner -> inner.getMessage())
                    .filter(StringUtils::isNotEmpty)
                    .map(msg -> String.format("inner: %s", msg))
                    .map(msg -> messages.add(msg));
            Optional.ofNullable(inner)
                    .map(inner -> getApiExceptionDetails(inner))
                    .filter(StringUtils::isNotEmpty)
                    .map(msg -> String.format("details: %s", msg))
                    .map(msg -> messages.add(msg));
        } while (false);
        for (int i = 0 ; i < messages.size() ; i++) {
            String message = messages.get(i);
            if (0 == i) message = message.substring(0, 1).toUpperCase() + message.substring(1);
            if (0 != i) builder.append("; ");
            builder.append(message);
        }
        return builder.toString();
    }

    @Override
    public void printStackTrace(PrintStream s) {
        super.printStackTrace(s);
        if (null != inner)
            inner.printStackTrace(s);
    }
}
