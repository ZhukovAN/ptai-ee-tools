package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.scan.errors.Error;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;

import java.io.File;
import java.util.List;
import java.util.UUID;

/**
 *
 */
public interface GenericAstTasks {
    void upload(@NonNull final UUID projectId, @NonNull final File sources) throws GenericException;

    UUID startScan(@NonNull final UUID projectId, boolean fullScanMode) throws GenericException;

    String getScanResultUrl(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException;

    void waitForComplete(@NonNull ScanBrief scanBrief) throws InterruptedException;
    void stop(@NonNull UUID scanResultId) throws GenericException;


    /**
     * Create scan brief skeleton that contains scan setings only. Statistic, state and policyState
     * are to be defined after scan is complete
     * @param projectId
     * @param scanResultId
     * @return
     * @throws GenericException
     */
    @NonNull
    ScanBrief createScanBrief(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException;

    /**
     * Append scan statistic, state and policy state to scan brief
     * @param scanBrief
     * @throws GenericException
     */
    void appendStatistics(@NonNull final ScanBrief scanBrief) throws GenericException;

    ScanResult getScanResult(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException;

    ScanResult getScanResult(@NonNull final ScanBrief scanBrief) throws GenericException;

    List<Error> getScanErrors(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException;
}
