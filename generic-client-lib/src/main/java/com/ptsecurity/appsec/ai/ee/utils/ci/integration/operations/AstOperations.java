package com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanBriefDetailed;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;

import java.io.File;
import java.util.UUID;

/**
 * As AST job may be executed in different environments, i.e. as part of
 * CI plugin or as a desktop application, there's need for different
 * implementations for some functions like file operations, safe job
 * termination etc. This interface defines set of methods that are used
 * inside AST job and are to be implemented differently
 */
public interface AstOperations {
    /** Create zipped sources archive. Method marked as abstract as different
     * environments may require different approaches to this procedure.
     * For example, Jenkins plugin may be executed on a remote build agent
     * and it's recommended to work with files using MasterToSlaveCallable approach
     * Method may return null if resulting archive file is empty
     * @return Zip archive with sources ready to be uploaded to PT AI server
     */
    File createZip() throws GenericException;

    /**
     * Callback method is being called when AST job is started on PT AI server.
     * AstJob descendants may use this callback to prepare for safe build
     * termination. For example, CLI plugin may create
     * Runtime.getRuntime().addShutdownHook graceful termination hook and
     * call AST stop API to terminate job on a PT AI server
     */
    void scanStartedCallback(@NonNull final UUID projectId, @NonNull final UUID scanResultId) throws GenericException;

    /**
     * Callback method is being called when AST job is finished on PT AI server. AstJob descendants may use
     * this callback to relax for safe build termination as there's no need to gracefully stop AST if
     * descendant is terminated using i.e. Ctrl-C
     * @param scanBrief Brief scan results. As this callback may be used by AstOperations
     *                  implementations to get scan results there's need to check if
     *                  scan brief state isn't ABORTED_FROM_PTAI as PT AI viewer removes scan
     * @throws GenericException
     */
    void scanCompleteCallback(@NonNull final ScanBrief scanBrief, @NonNull final ScanBriefDetailed.Performance performance) throws GenericException;
}
