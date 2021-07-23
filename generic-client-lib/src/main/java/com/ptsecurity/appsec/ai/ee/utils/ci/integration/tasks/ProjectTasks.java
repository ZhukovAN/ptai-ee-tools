package com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks;

import com.ptsecurity.appsec.ai.ee.scan.settings.AiProjScanSettings;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import lombok.NonNull;

import java.util.UUID;

public interface ProjectTasks {
    UUID searchProject(@NonNull final String name) throws GenericException;

    String searchProject(@NonNull final UUID id) throws GenericException;

    UUID getLatestAstResult(@NonNull final UUID id) throws GenericException;

    UUID getLatestCompleteAstResult(@NonNull final UUID id) throws GenericException;

    UUID setupFromJson(@NonNull final AiProjScanSettings settings, final Policy[] policy) throws GenericException;
}
