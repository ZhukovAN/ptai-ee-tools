package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import okio.Buffer;
import okio.BufferedSource;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
public class LoggingInterceptor implements Interceptor {
    @NotNull
    @Override
    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();

        long requestTime = System.nanoTime();
        log.trace("Sending {} request to {}", request.method(), request.url());
        log.trace("Request headers: {}", request.headers());
        if (null != request.body())
            traceBody(request.headers(), request.body());

        Response response = chain.proceed(request);
        long responseTime = System.nanoTime();
        log.trace(String.format("Received %d response for %s in %.1fms",
                response.code(), response.request().url(), (responseTime - requestTime) / 1e6d));

        log.trace("Response headers: {}", response.headers());
        if (null != response.body()) {
            BufferedSource source = response.body().source();
            source.request(Long.MAX_VALUE); // Buffer the entire body.
            Buffer buffer = source.getBuffer();
            String bufferData = buffer.clone().readString(StandardCharsets.UTF_8);
            if (5 * 1024 * 1024 >= bufferData.length()) {
                log.trace("Response body: {}", bufferData);
            } else
                log.trace("Response body skipped as it {} bytes long", bufferData.length());
        }
        return response;
    }

    private boolean encodingUnknown(@NonNull final Headers headers) {
        final String encoding = headers.get("Content-Encoding");
        return !("identity".equalsIgnoreCase(encoding) || "gzip".equalsIgnoreCase(encoding));
    }

    protected void traceBody(
            @NonNull final Headers headers,
            @NonNull final RequestBody body) throws IOException {
        long contentLength = body.contentLength();
        String bodySize = -1L != body.contentLength() ? contentLength + " byte" : "unknown";
        log.trace("Request body size: {}", bodySize);

        if (!"application/json".equalsIgnoreCase(headers.get("Content-Type"))) return;

        Buffer buffer = new Buffer();
        body.writeTo(buffer);
        log.trace("Request body: {}", buffer.readString(StandardCharsets.UTF_8));
    }
}
