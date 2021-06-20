package com.ptsecurity.appsec.ai.ee.ptai.server;

import lombok.*;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.Callable;

@Slf4j
@SuperBuilder
@NoArgsConstructor
@ToString
public class ApiHelper {
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
        }, errorMessage);
    }
}
