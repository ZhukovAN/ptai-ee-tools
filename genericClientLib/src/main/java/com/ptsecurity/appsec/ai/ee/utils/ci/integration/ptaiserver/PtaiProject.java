package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiException;
import com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.ApiResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class PtaiProject extends Client {
    @Getter
    @Setter
    protected String name;

    public UUID searchProject() throws PtaiServerException {
        ApiResponse<List<com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.Project>> projects = null;
        try {
            projects = this.prjApi.apiProjectsGetWithHttpInfo(true);
            UUID projectId = null;
            for (com.ptsecurity.appsec.ai.ee.ptai.server.projectmanagement.rest.Project prj : projects.getData())
                if (this.name.equals(prj.getName()))
                    return prj.getId();
        } catch (ApiException e) {
            throw new PtaiServerException(e.getMessage(), e);
        }
        return null;
    }

    public void upload(Transfers transfers, String srcFolderName) throws PtaiClientException, PtaiServerException {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String transfersJson = objectMapper.writeValueAsString(transfers);
            FileCollector collector = new FileCollector(transfers, this);
            File srcFolder = new File(srcFolderName);
            if ((null == srcFolder) || !srcFolder.exists() || !srcFolder.canRead())
                throw new PtaiClientException("Invalid source folder");
            File destFile = File.createTempFile("PTAI_", ".zip");
            this.log("Zipped sources are in  %s\r\n", destFile.getAbsolutePath());
            collector.collect(srcFolder, destFile);

            // Search for project
            UUID projectId = this.searchProject();
            if (null == projectId)
                throw new PtaiClientException("PT AI project not found");
            // Upload project sources
            com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiResponse<Void> res = this.storeApi.apiStoreSourcesByProjectIdPostWithHttpInfo(
                    projectId,
                    destFile,
                    null,null,null,null,null,null);
            this.log("Sources upload result is %d\r\n", res.getStatusCode());
            destFile.delete();
            if (200 != res.getStatusCode())
                throw new PtaiClientException("Sources upload failed");
        } catch (IOException e) {
            this.log(e);
            throw new PtaiClientException(e.getMessage(), e);
        } catch (com.ptsecurity.appsec.ai.ee.ptai.server.filesstore.ApiException e) {
            this.log(e);
            throw new PtaiServerException(e.getMessage(), e);
        }
    }
}
