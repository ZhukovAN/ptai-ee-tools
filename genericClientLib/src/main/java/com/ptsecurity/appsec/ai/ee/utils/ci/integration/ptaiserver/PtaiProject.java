package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiResponse;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonPolicy;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils.JsonSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.joda.time.DateTime;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;

public class PtaiProject extends Client {
    @Getter
    @Setter
    protected String name;

    @Getter
    @Setter
    protected String jsonPolicy = "";

    @Getter
    @Setter
    protected String jsonSettings = "";

    public UUID searchProject() throws PtaiServerException {
        ApiResponse<List<com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.Project>> projects = null;
        try {
            projects = this.prjApi.getWithHttpInfo(true);
            UUID projectId = null;
            for (com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.Project prj : projects.getData())
                if (this.name.equals(prj.getName()))
                    return prj.getId();
        } catch (ApiException e) {
            throw new PtaiServerException(e.getMessage(), e);
        }
        return null;
    }


    public UUID createProject(String projectName) throws PtaiClientException, PtaiServerException {
        try {
            CreateProjectModel model = new CreateProjectModel();

            Project project = new Project();
            FieldUtils.writeField(project, "id", UUID.randomUUID(), true);
            project.setName(projectName);
            project.setCreationDate(DateTime.now());
            model.setProject(project);

            IScanSettings scanSettings = new IScanSettings();
            FieldUtils.writeField(scanSettings, "id", UUID.randomUUID(), true);
            model.setScanSettings(scanSettings);

            FieldUtils.writeField(project, "settingsId", scanSettings.getId(), true);

            Project res = this.prjApi.post(model);
            return res.getId();
        } catch (ApiException | IllegalAccessException e) {
            throw new PtaiServerException(e.getMessage(), e);
        }
    }

    public UUID createProject(JsonSettings settings) throws PtaiClientException, PtaiServerException {
        return this.createProject(settings.ProjectName);
    }

    public void deleteProject() throws PtaiClientException, PtaiServerException {
        UUID projectId = this.searchProject();
        if (null == projectId)
            throw new PtaiClientException("PT AI project not found");
        try {
            this.prjApi.delete(projectId);
        } catch (ApiException e) {
            throw new PtaiServerException(e.getMessage(), e);
        }
    }

    public void upload(Transfers transfers, String srcFolderName) throws PtaiClientException, PtaiServerException {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String transfersJson = objectMapper.writeValueAsString(transfers);
            FileCollector collector = new FileCollector(transfers, this);
            File srcFolder = new File(srcFolderName);
            if ((null == srcFolder) || !srcFolder.exists() || !srcFolder.canRead()) {
                String reason = "Unknown";
                if (null == srcFolder)
                    reason = "Null value passed";
                else if (!srcFolder.exists())
                    reason = srcFolderName + " does not exist";
                else if (!srcFolder.canRead())
                    reason = srcFolderName + " can not be read";
                throw new PtaiClientException("Invalid source folder, " + reason);
            } else
                this.log("Sources to be packed are in ", srcFolderName);
            File destFile = File.createTempFile("PTAI_", ".zip");
            this.log("Zipped sources are in  %s\r\n", destFile.getAbsolutePath());

            List<FileCollector.FileEntry> fileEntries = collector.collectFiles(srcFolder);
            /*
            File jsonSettingsFile = File.createTempFile("settings_", ".aiproj");
            if (StringUtils.isNotEmpty(jsonSettings)) {
                FileWriter writer = new FileWriter(jsonSettingsFile);
                writer.write(jsonSettings);
                writer.close();
                fileEntries.add(new FileCollector.FileEntry(jsonSettingsFile.getAbsolutePath(), "SETTINGS" + "/" + "settings.aiproj"));
            }
            File jsonPolicyFile = File.createTempFile("policy_", ".json");
            if (StringUtils.isNotEmpty(jsonPolicy)) {
                FileWriter writer = new FileWriter(jsonPolicyFile);
                writer.write(jsonPolicy);
                writer.close();
                fileEntries.add(new FileCollector.FileEntry(jsonPolicyFile.getAbsolutePath(), "SETTINGS" + "/" + "policy.json"));
            }
            */
            collector.packCollectedFiles(destFile, fileEntries);

            // Search for project
            UUID projectId = this.searchProject();
            if (null == projectId)
                throw new PtaiClientException("PT AI project not found");
            // Upload project sources
            com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiResponse<Void> res = this.storeApi.uploadSourcesWithHttpInfo(
                    projectId,
                    destFile,
                    null,null,null,null,null,null,
                    null,null,null,null,null);
            this.log("Sources upload result is %d\r\n", res.getStatusCode());
            // jsonPolicyFile.delete();
            // jsonSettingsFile.delete();
            destFile.delete();
            if (200 != res.getStatusCode())
                throw new PtaiClientException("Sources upload failed");
        } catch (IOException | ArchiveException e) {
            this.log(e);
            throw new PtaiClientException(e.getMessage(), e);
        } catch (com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiException e) {
            this.log(e);
            throw new PtaiServerException(e.getMessage(), e);
        }
    }
}
