package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.ToString;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.Callable;

@Slf4j
@SuperBuilder
@NoArgsConstructor
@ToString
public class CallHelper {
    /**
     * Call method that may throw an Exception and wrap that exception into ApiException
     * @param call Function to be called
     * @param errorMessage Generic error message if function call failed
     * @param <V> Function return type
     * @return Finction call result
     * @throws GenericException Exception that wraps internal error and uses errorMessage
     * as error cause description
     */
    public static <V> V call(@NonNull Callable<V> call, @NonNull String errorMessage) throws GenericException {
        return call(call, errorMessage, false);
    }

    public static <V> V call(@NonNull Callable<V> call, @NonNull String errorMessage, final boolean warningOnly) throws GenericException {
        try {
            return call.call();
        } catch (Exception e) {
            if (!warningOnly) throw GenericException.raise(errorMessage, e);
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

    public static void call(@NonNull Runnable call, @NonNull String errorMessage) throws GenericException {
        call(call, errorMessage, false);
    }

    public static void call(@NonNull Runnable call, @NonNull String errorMessage, final boolean warningOnly) throws GenericException {
        call(() -> {
            call.run();
            return null;
        }, errorMessage);
    }
}
