package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import okio.Buffer;
import okio.BufferedSink;
import okio.BufferedSource;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings.SettingInfo.LOGGING_HTTP_REQUEST_MAX_BODY_SIZE;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.AdvancedSettings.SettingInfo.LOGGING_HTTP_RESPONSE_MAX_BODY_SIZE;

@Slf4j
@AllArgsConstructor
public class LoggingInterceptor implements Interceptor {
    @NonNull
    protected AdvancedSettings advancedSettings = AdvancedSettings.getDefault();

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

        int maxBody = advancedSettings.getInt(LOGGING_HTTP_RESPONSE_MAX_BODY_SIZE);
        if (0 != maxBody && null != response.body()) {
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
        String bodySize = -1L != contentLength ? contentLength + " byte" : "unknown";
        log.trace("Request body size: {}", bodySize);

        if (!"application/json".equalsIgnoreCase(headers.get("Content-Type"))) {
            log.trace("Non-JSON request body skipped");
            return;
        }

        Buffer buffer = new Buffer();
        body.writeTo(buffer);
        int maxBody = advancedSettings.getInt(LOGGING_HTTP_REQUEST_MAX_BODY_SIZE);

        if (maxBody >= contentLength) {
            String stringBody = buffer.readString(StandardCharsets.UTF_8);
            log.trace("Request body: {}", StringUtils.isEmpty(stringBody) ? "[empty]" : stringBody);
        } else {
            log.trace("Request body trimmed to first {} bytes as it {} bytes long", maxBody, contentLength);
            String stringBody = buffer.readString(maxBody, StandardCharsets.UTF_8);
            log.trace("Trimmed request body: {}", StringUtils.isEmpty(stringBody) ? "[empty]" : stringBody);
        }
    }
}
