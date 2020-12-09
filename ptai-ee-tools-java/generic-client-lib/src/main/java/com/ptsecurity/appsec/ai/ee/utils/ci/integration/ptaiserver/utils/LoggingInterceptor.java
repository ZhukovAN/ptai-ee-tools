package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import lombok.extern.slf4j.Slf4j;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;
import okio.Buffer;
import okio.BufferedSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
public class LoggingInterceptor implements Interceptor {
    @Override public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();

        long requestTime = System.nanoTime();
        log.trace(String.format("Sending request to %s", request.url()));
        log.trace(String.format("Request headers: %s", request.headers()));
        if (null != request.body())
            log.trace(String.format("Request body: %s", request.body().toString()));

        Response response = chain.proceed(request);
        long responseTime = System.nanoTime();
        log.trace(String.format("Received %d response for %s in %.1fms",
                response.code(), response.request().url(), (responseTime - requestTime) / 1e6d));

        log.trace(String.format("Response headers: %s", response.headers()));
        if (null != response.body()) {
            BufferedSource source = response.body().source();
            source.request(Long.MAX_VALUE); // Buffer the entire body.
            Buffer buffer = source.getBuffer();
            // TODO: Add buffer size verification
            String bufferData = buffer.clone().readString(StandardCharsets.UTF_8).toString();
            log.trace(String.format("Response body: %s", bufferData));
        }
        return response;
    }
}
