package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.json;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ptsecurity.appsec.ai.ee.helpers.json.JsonSettingsHelper;
// import com.ptsecurity.appsec.ai.ee.scan.settings.AbstractAiProjScanSettings.ScanAppType;
import com.ptsecurity.misc.tools.TempFile;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.SneakyThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class JsonSettingsTestHelper extends JsonSettingsHelper {
    public JsonSettingsTestHelper(@NonNull String json) throws GenericException {
        super(json);
    }

    protected static void setBooleanField(@NonNull final ObjectNode node, @NonNull final String fieldName, final boolean fieldValue) {
        node.put(fieldName, fieldValue);
    }

    private final String CUSTOM_PARAMETERS = "CustomParameters";

    public void setCustomParameters(@NonNull final String value) {
        setStringField(root, CUSTOM_PARAMETERS, value);
    }

    public String getCustomParameters() {
        return getStringField(root, CUSTOM_PARAMETERS);
    }

    public JsonSettingsTestHelper customParameters(@NonNull final String value) {
        setCustomParameters(value);
        return this;
    }

    private final String SCAN_APP_TYPE = "ScanAppType";
/*
    public void setScanAppType(final ScanAppType... values) {
        // noinspection ConstantConditions
        do {
            if (null == values || 0 == values.length) break;
            Set<ScanAppType> valuesSet = new HashSet<>();
            Collections.addAll(valuesSet, values);
            if (valuesSet.isEmpty()) break;
            String valuesStr = valuesSet.stream().map(ScanAppType::value).collect(Collectors.joining(", "));
            root.put(SCAN_APP_TYPE, valuesStr);
            return;
        } while (false);
        if (root.has(SCAN_APP_TYPE)) root.remove(SCAN_APP_TYPE);
    }

    public JsonSettingsTestHelper scanAppType(final ScanAppType... values) {
        setScanAppType(values);
        return this;
    }

    private final String USE_ENTRY_POINT_ANALYSIS = "IsUseEntryAnalysisPoint";

    public void setIsUseEntryAnalysisPoint(final boolean value) {
        setBooleanField(root, USE_ENTRY_POINT_ANALYSIS, value);
    }

    public JsonSettingsTestHelper isUseEntryAnalysisPoint(final boolean value) {
        setIsUseEntryAnalysisPoint(value);
        return this;
    }

    private final String DOWNLOAD_DEPENDENCIES = "IsDownloadDependencies";
    public void setIsDownloadDependencies(final boolean value) {
        setBooleanField(root, DOWNLOAD_DEPENDENCIES, value);
    }

    public JsonSettingsTestHelper isDownloadDependencies(final boolean value) {
        setIsDownloadDependencies(value);
        return this;
    }

    private final String USE_PUBLIC_METHOD_ANALYSIS = "IsUsePublicAnalysisMethod";

    public void setIsUsePublicAnalysisMethod(final boolean value) {
        setBooleanField(root, USE_PUBLIC_METHOD_ANALYSIS, value);
    }

    public JsonSettingsTestHelper isUsePublicAnalysisMethod(final boolean value) {
        setIsUsePublicAnalysisMethod(value);
        return this;
    }

    private final String USE_TAINT_ANALYSIS = "UseTaintAnalysis";

    public void setUseTaintAnalysis(final boolean value) {
        setBooleanField(root, USE_TAINT_ANALYSIS, value);
    }

    public JsonSettingsHelper useTaintAnalysis(final boolean value) {
        setUseTaintAnalysis(value);
        return this;
    }

    private final String USE_PM_ANALYSIS = "UsePmAnalysis";

    public void setUsePmAnalysis(final boolean value) {
        setBooleanField(root, USE_PM_ANALYSIS, value);
    }

    public JsonSettingsTestHelper usePmAnalysis(final boolean value) {
        setUsePmAnalysis(value);
        return this;
    }

    @SneakyThrows
    public Path serializeToFile() {
        String data = this.serialize();
        TempFile file = TempFile.createFile();
        Files.write(file.toPath(), data.getBytes(StandardCharsets.UTF_8));
        return file.toPath();
    }

    public JsonSettingsTestHelper randomizeProjectName() {
        setProjectName("junit-" + UUID.randomUUID());
        return this;
    }
    */
}
