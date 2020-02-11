package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.impl.EnglishReasonPhraseCatalog;

import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@NoArgsConstructor
public class BaseClientException extends RuntimeException {
    // Root cause of this "boxing" exception
    @Getter
    protected Exception inner = null;

    private static String apiExceptionClassRegex = "com\\.ptsecurity\\.appsec\\.ai\\.ee\\.[\\w\\.]+\\.ApiException";

    public BaseClientException(String message, Exception inner) {
        super(message);
        this.inner = inner;
    }

    public BaseClientException(String message) {
        this(message, null);
    }

    public static String getInnerExceptionDetails(Exception exception) {
        if (!exception.getClass().getCanonicalName().matches(apiExceptionClassRegex))
            return "";
        try {
            Method getCode = exception.getClass().getMethod("getCode");
            int code = (int) getCode.invoke(exception);
            if (0 == code)
                return "";
            String reason = EnglishReasonPhraseCatalog.INSTANCE.getReason(code, null);
            return String.format("Code: %d, reason: %s", code, reason);
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            return "";
        }
    }

    public static String getInnerExceptionData(Exception exception) {
        if (!exception.getClass().getCanonicalName().matches(apiExceptionClassRegex))
            return "";
        try {
            Method getResponseBody = exception.getClass().getMethod("getResponseBody");
            return (String) getResponseBody.invoke(exception);
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            return "";
        }
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
                    .map(inner -> getInnerExceptionDetails(inner))
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
