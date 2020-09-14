package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver;

import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiResponse;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.deprecated.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiServerException;
import com.ptsecurity.appsec.ai.ee.utils.json.ScanSettings;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.reflect.FieldUtils;

import java.io.File;
import java.time.OffsetDateTime;
import java.util.*;

public class PtaiProject extends Client {
    @Getter
    @Setter
    protected String name;

    public static Optional<UUID> searchProject(ProjectsApi api, String name) throws PtaiServerException {
        ApiResponse<List<Project>> projects = null;
        try {
            projects = api.getWithHttpInfo(true);
            UUID projectId = null;
            for (Project prj : projects.getData())
                if (name.equals(prj.getName()))
                    return Optional.of(prj.getId());
        } catch (ApiException e) {
            throw new PtaiServerException("PT AI EE project search failed", e);
        }
        return Optional.empty();
    }

    public UUID searchProject() throws PtaiServerException {
        return searchProject(this.prjApi, this.name).orElse(null);
    }

    public static UUID createProject(ProjectsApi api, String name) throws PtaiServerException {
        try {
            CreateProjectModel model = new CreateProjectModel();

            Project project = new Project();
            FieldUtils.writeField(project, "id", UUID.randomUUID(), true);
            project.setName(name);
            project.setCreationDate(OffsetDateTime.now());
            model.setProject(project);

            IScanSettings scanSettings = new IScanSettings();
            FieldUtils.writeField(scanSettings, "id", UUID.randomUUID(), true);

            model.setScanSettings(scanSettings);

            FieldUtils.writeField(project, "settingsId", scanSettings.getId(), true);

            Project res = api.post(model);
            return res.getId();
        } catch (ApiException | IllegalAccessException e) {
            throw new PtaiServerException("PT AI EE project create failed", e);
        }
    }

    public UUID createProject(String name) throws PtaiServerException {
        return createProject(this.prjApi, name);
    }

    public UUID createProject(ScanSettings settings) throws PtaiClientException, PtaiServerException {
        return this.createProject(settings.getProjectName());
    }

    public void deleteProject() throws PtaiClientException, PtaiServerException {
        UUID projectId = this.searchProject();
        if (null == projectId)
            throw new PtaiClientException("PT AI project not found");
        try {
            this.prjApi.delete(projectId);
        } catch (ApiException e) {
            throw new PtaiServerException("PT AI EE project delete failed", e);
        }
    }

    public void upload(File file) throws PtaiClientException, PtaiServerException {
        try {
            out("Zipped sources are in  %s", file.getAbsolutePath());

            // Search for project
            UUID projectId = this.searchProject();
            if (null == projectId)
                throw new PtaiClientException("PT AI project not found");
            // Upload project sources
            com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiResponse<Void> res = this.storeApi.uploadSourcesWithHttpInfo(
                    projectId,
                    file,
                    null,null,null,null,null,null,
                    null,null,null,null,null);
            out("Sources upload result is %d", res.getStatusCode());
            file.delete();
            if (200 != res.getStatusCode())
                throw new PtaiClientException("Sources upload failed");
        } catch (com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiException e) {
            if (file.exists())
                file.delete();
            this.log(e);
            throw new PtaiServerException("Sources upload failed", e);
        }
    }
}
