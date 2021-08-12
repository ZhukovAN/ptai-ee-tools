package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.scan.errors.Error;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import lombok.NonNull;

import java.io.File;
import java.util.List;
import java.util.UUID;

public interface GenericAstTasks {
    void upload(@NonNull final UUID projectId, @NonNull final File sources) throws GenericException;

    UUID startScan(@NonNull final UUID projectId, boolean fullScanMode) throws GenericException;

    String getScanResultUrl(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException;

    ScanBrief.State waitForComplete(@NonNull UUID projectId, @NonNull final UUID scanResultId) throws GenericException;
    void stop(@NonNull UUID scanResultId) throws GenericException;

    ScanBrief getScanBrief(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException;
    ScanResult getScanResult(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException;

    List<Error> getScanErrors(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException;
}
