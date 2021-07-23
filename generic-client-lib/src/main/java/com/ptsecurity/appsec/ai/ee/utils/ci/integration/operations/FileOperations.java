package com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations;

import lombok.NonNull;

import java.io.File;

/**
 * As AST job may be executed in different environments, i.e. as part of
 * CI plugin or as a desktop application, there's need for different
 * implementations for some functions like file operations. This
 * interface defines set of methods that are used inside misc jobs and
 * are to be implemented differently
 */
public interface FileOperations {

    /** Method saves @data from file to artifact named @name. Method marked as
     * abstract as different descendants may use different approaches. For example,
     * Jenkins plugin needs to use MasterToSlaveCallable approach as workspace
     * may be located on a remote build agent
     * @param name File name to be saved
     * @param data Artifact data to save
     */
    void saveArtifact(@NonNull final String name, @NonNull final File data);

    /** Method saves @data buffer to artifact named @name. Method marked as
     * abstract as different descendants may use different approaches. For example,
     * Jenkins plugin needs to use MasterToSlaveCallable approach as workspace
     * may be located on a remote build agent
     * @param name File name to be saved
     * @param data Artifact data to save
     */
    void saveArtifact(@NonNull final String name, @NonNull final byte[] data);
}
