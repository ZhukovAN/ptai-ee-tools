package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.operations;

import com.ptsecurity.appsec.ai.ee.ptai.server.ApiException;
import com.ptsecurity.appsec.ai.ee.scanresult.ScanResult;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.Project;
import lombok.NonNull;

import java.io.File;
import java.util.Map;
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
    File createZip() throws ApiException;

    /**
     * Callback method is being called when AST job is started on PT AI server.
     * AstJob descendants may use this callback to prepare for safe build
     * termination. For example, CLI plugin may create
     * Runtime.getRuntime().addShutdownHook graceful termination hook and
     * call AST stop API to terminate job on a PT AI server
     */
    void scanStartedCallback(@NonNull final Project project, @NonNull final UUID scanResultId) throws ApiException;

    /**
     * Callback method is being called when AST job is finished on PT AI server.
     * AstJob descendants may use this callback to relax for safe build
     * termination as there's no need to gracefully stop AST if descendant
     * is terminated using i.e. Ctrl-C
     */
    void scanCompleteCallback(@NonNull final Project project, @NonNull final ScanResult scanResult) throws ApiException;

    /**
     * Method replaces macro expressions like ${FOO} in the input text using dictionary. AstJob's
     * method doesn't do any replacements as those are to be implemented in its descendants.
     * For example, Jenkins plugin may override this implementation
     * with hudson.Util.replaceMacro call
     * @param value String with macro expressions to be replaced
     * @param replacements Dictionary with name / value pairs
     * @return String with macro substitutions complete
     */
    String replaceMacro(@NonNull final String value, final Map<String, String> replacements);
}
