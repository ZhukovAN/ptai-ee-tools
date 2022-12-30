package com.ptsecurity.appsec.ai.ee.server.helpers;

import com.ptsecurity.misc.tools.Jwt;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.misc.tools.helpers.CallHelper;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

import static com.ptsecurity.appsec.ai.ee.server.integration.rest.Connection.CONNECTION;
import static com.ptsecurity.misc.tools.helpers.CallHelper.call;
import static org.joor.Reflect.on;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
public abstract class AbstractApiHelper {
    public enum TokenType {
        CI, CI_AGENT, ROOT
    }

    public static final Map<TokenType, Jwt> JWT = new HashMap<>();

    /**
     * Method authenticates API clients using three different schemas: two API tokens (CI and CI + scan agent)
     * and root user login / password. These JWT's are used in integration tests
     */
    public abstract void authenticate();

    protected static final List<Object> API = new ArrayList<>();

    public static void setJwt(String accessToken) {
        for (Object api : API) {
            on(api).call("getApiClient").call("setBasePath", CONNECTION().getUrl());
            on(api).call("getApiClient").call("setApiKey", accessToken);
            on(api).call("getApiClient").call("setApiKeyPrefix", "Bearer");
            on(api).call("getApiClient").call("setVerifyingSsl", false);
        }
    }

    public static void setJwt(TokenType tokenType) {
        log.trace("Set {} JWT", tokenType);
        setJwt(JWT.get(tokenType).getAccessToken());
    }

    public static void checkApiCall(@NonNull CallHelper.Runnable call) {
        checkApiCall(call, TokenType.CI);
    }

    public static <V> V checkApiCall(@NonNull CallHelper.Callable<V> call) {
        return checkApiCall(call, TokenType.CI);
    }

    public static void checkApiCall(@NonNull CallHelper.Runnable call, TokenType minimumAllowed) {
        checkApiCall(() -> {
            call.run();
            return null;
        }, minimumAllowed);
    }

    public static <V> V checkApiCall(@NonNull CallHelper.Callable<V> call, TokenType minimumAllowed) {
        StackTraceElement stackTraceElement = Thread.currentThread().getStackTrace()[2];
        log.trace("Call from {} : {}", stackTraceElement.getFileName(), stackTraceElement.getLineNumber());

        V result = null;
        for (TokenType tokenType : TokenType.values()) {
            setJwt(tokenType);
            if (0 > tokenType.compareTo(minimumAllowed)) {
                log.trace("Check API call fails as {} token less than minimum allowed {}", tokenType, minimumAllowed);
                assertThrows(GenericException.class, () -> call(call, "API call failed"));
            } else {
                log.trace("Check API call succeeds as {} token equal or greater than minimum allowed {}", tokenType, minimumAllowed);
                result = assertDoesNotThrow(() -> call(call, "API call failed"));
            }
        }
        return result;
    }
}
