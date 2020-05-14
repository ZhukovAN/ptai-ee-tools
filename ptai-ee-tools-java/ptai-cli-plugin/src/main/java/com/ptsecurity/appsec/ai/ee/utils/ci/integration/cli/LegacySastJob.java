package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.aic.ExitCode;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.PtaiProject;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import lombok.Builder;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.net.URL;
import java.nio.file.Path;
import java.util.Optional;
import java.util.UUID;

@Builder
public class LegacySastJob extends Base {
    protected final URL jenkinsUrl;
    protected final URL ptaiUrl;

    protected final String sastJob;
    protected final String project;

    protected Path truststore;
    protected String truststoreType;
    protected String truststorePass;
    protected final Path keystore;
    protected final String keystoreType;
    protected final String keystorePass;

    protected final Path input;
    protected final Path output;
    protected String includes;
    protected String excludes;
    protected final String node;
    protected final String username;
    protected final String password;

    public Integer execute() {
        PtaiProject ptaiPrj = new PtaiProject();
        ptaiPrj.setVerbose(verbose);
        ptaiPrj.setConsoleLog(System.out);
        ptaiPrj.setUrl(ptaiUrl.toString());
        ptaiPrj.setKeyStoreFile(keystore.toString());
        ptaiPrj.setKeyStoreType(keystoreType);
        ptaiPrj.setKeyStorePassword(keystorePass);
        ptaiPrj.setTrustStoreFile(truststore.toString());
        ptaiPrj.setTrustStoreType(truststoreType);
        ptaiPrj.setTrustStorePassword(truststorePass);
        ptaiPrj.setName(project);
        // Connect to PT AI server
        try {
            // Try to authenticate
            String ptaiToken = ptaiPrj.init();
            if (StringUtils.isEmpty(ptaiToken))
                throw new PtaiServerException("PT AI server authentication failed", null);
            if (verbose)
                System.out.println("PT AI server authentication success. Token starts with " + ptaiToken.substring(0, 10));

            // Search for project
            UUID projectId = ptaiPrj.searchProject();
            if (null == projectId)
                throw new PtaiServerException("PT AI project not found", null);
            if (verbose)
                System.out.println("PT AI project found. ID starts with " + projectId.toString().substring(0, 4));
            // Upload project sources
            Transfers transfers = new Transfers();
            Transfer transfer = new Transfer();
            if (StringUtils.isNotEmpty(includes))
                transfer.setIncludes(includes);
            if (StringUtils.isNotEmpty(excludes))
                transfer.setExcludes(excludes);
            transfers.addTransfer(transfer);
            FileCollector collector = new FileCollector(transfers, null);
            File zip = FileCollector.collect(transfers, input.toFile(), this);
            ptaiPrj.upload(zip);
            // Let's start analysis
            com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.SastJob jenkinsSastJob = new com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.SastJob();
            jenkinsSastJob.setVerbose(verbose);
            jenkinsSastJob.setConsoleLog(System.out);
            jenkinsSastJob.setUrl(jenkinsUrl.toString());
            jenkinsSastJob.setJobName(sastJob);
            if (null != truststore) {
                jenkinsSastJob.setTrustStoreFile(truststore.toString());
                jenkinsSastJob.setTrustStoreType(truststoreType);
                jenkinsSastJob.setTrustStorePassword(truststorePass);
            }
            jenkinsSastJob.setProjectName(ptaiPrj.getName());
            jenkinsSastJob.setNodeName(StringUtils.isEmpty(node) ? Base.DEFAULT_PTAI_NODE_NAME : node);
            // Set authentication parameters
            if (StringUtils.isNotEmpty(username)) {
                jenkinsSastJob.setUserName(username);
                jenkinsSastJob.setPassword(password);
            }
            jenkinsSastJob.init();
            return jenkinsSastJob.execute(output.toString());
        } catch (JenkinsClientException | PtaiClientException e) {
            System.out.println(e.toString());
            if (verbose)
                Optional.ofNullable(e.getInner())
                        .ifPresent(inner -> inner.getMessage());
            return ExitCode.CODE_UNKNOWN_ERROR.getCode();
        }
    }
}
