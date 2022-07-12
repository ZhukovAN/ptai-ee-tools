package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import okio.Buffer;
import okio.BufferedSource;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings.HTTP_RESPONSE_MAX_BODY_SIZE;

@Slf4j
public class LoggingInterceptor implements Interceptor {
    /**
     * Maximum response body size to be output to log
     */
    protected static int HTTP_RESPONSE_MAX_BODY_SIZE_VALUE = 10 * 1024;

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

        int maxBody = 102400;
        if (null != response.body()) {
            BufferedSource source = response.body().source();
            source.request(Long.MAX_VALUE); // Buffer the entire body.
            Buffer buffer = source.getBuffer();
            if (buffer.size() < maxBody) maxBody = (int) buffer.size();
            String bufferData = buffer.clone().readString(maxBody, StandardCharsets.UTF_8);

            if (maxBody >= bufferData.length()) {
                log.trace("Response body: {}", StringUtils.isEmpty(bufferData) ? "[empty]" : bufferData);
            } else {
                log.trace("Response body trimmed to first {} bytes as it {} bytes long", maxBody, bufferData.length());
                log.trace("Trimmed response body: {}", bufferData.substring(0, maxBody));
            }
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
