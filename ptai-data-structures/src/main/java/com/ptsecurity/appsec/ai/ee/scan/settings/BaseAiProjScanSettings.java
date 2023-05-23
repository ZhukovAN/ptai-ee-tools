package com.ptsecurity.appsec.ai.ee.scan.settings;

import com.jayway.jsonpath.JsonPath;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import static java.lang.Boolean.TRUE;

@Slf4j
public abstract class BaseAiProjScanSettings {
    protected Object aiprojDocument;

    protected Boolean B(@NonNull final String path) {
        return B(aiprojDocument, path);
    }

    protected Integer I(@NonNull final String path) {
        return I(aiprojDocument, path);
    }

    protected String S(@NonNull final String path) {
        return S(aiprojDocument, path);
    }

    protected Boolean B(@NonNull final Object json, @NonNull final String path) {
        return TRUE.toString().equalsIgnoreCase(S(json, path));
    }

    protected Integer I(@NonNull final Object json, @NonNull final String path) {
        return Integer.parseInt(S(json, path));
    }

    protected String S(@NonNull final Object json, @NonNull final String path) {
        String res = JsonPath.read(json, path);
        log.trace("JsonPath {} = {}", path, res);
        return res;
    }
}
