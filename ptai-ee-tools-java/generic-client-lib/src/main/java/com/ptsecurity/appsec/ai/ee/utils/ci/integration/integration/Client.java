package com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration;

import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiClient;
import com.ptsecurity.appsec.ai.ee.ptai.integration.ApiException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.BaseClient;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.exceptions.BaseClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.jwt.JwtResponse;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.api.AdminControllerApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.api.DiagnosticControllerApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.api.PublicControllerApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.api.SastControllerApi;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.utils.JwtAuthenticator;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.integration.utils.TempFile;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiServerException;
import lombok.Getter;
import lombok.Setter;
import okhttp3.OkHttpClient;
import org.apache.commons.io.FileUtils;

import java.io.*;
import java.util.UUID;

@Getter @Setter
public class Client extends BaseClient {
    protected final SastControllerApi sastApi = new SastControllerApi(new ApiClient());
    protected final AdminControllerApi adminApi = new AdminControllerApi(new ApiClient());
    protected final PublicControllerApi publicApi = new PublicControllerApi(new ApiClient());
    protected final DiagnosticControllerApi diagnosticApi = new DiagnosticControllerApi(new ApiClient());

    protected String userName = null;
    protected String password = null;
    protected String clientId = null;
    protected String clientSecret = null;

    protected JwtResponse jwt = null;

    public void init() throws PtaiClientException {
        super.baseInit();
        super.initClients(sastApi, adminApi, publicApi, diagnosticApi);
    }

    @Override
    protected void initClient(Object client) throws BaseClientException {
        super.initClient(client);

        ApiClientHelper helper = new ApiClientHelper(client).init();
        OkHttpClient httpClient = helper.getHttpClient();
        httpClient = httpClient.newBuilder()
                .authenticator(new JwtAuthenticator(client, url, clientId, clientSecret, userName, password))
                .build();
        helper.setHttpClient(httpClient);
    }

    public void uploadZip(String projectName, File zip, long chunkSize) throws BaseClientException {
        try {
            String uploadId = UUID.randomUUID().toString();
            if (chunkSize > Integer.MAX_VALUE) throw new BaseClientException("File chunk size too big");
            log("Prepare to upload %s of sources", FileUtils.byteCountToDisplaySize(zip.length()));

            if (zip.length() <= chunkSize) {
                sastApi.uploadArtifacts(0, zip, projectName, 1, uploadId);
                log("Uploaded as single part");
            } else {
                try (InputStream in = new FileInputStream(zip)) {
                    final int bufferSize = 512 * 1024;
                    byte[] buffer = new byte[bufferSize];

                    long totalBytesToRead = zip.length();
                    // Some kind of math magic to ceil round division result
                    long partsNumber = (totalBytesToRead + chunkSize - 1) / chunkSize;

                    for (long i = 0; i < partsNumber; i++) {
                        long chunkBytesToRead = totalBytesToRead > chunkSize ? chunkSize : totalBytesToRead;
                        long readsNumber = (chunkBytesToRead + bufferSize - 1) / bufferSize;
                        try (TempFile chunkFile = new TempFile()) {
                            try (OutputStream out = new FileOutputStream(chunkFile.getFile().toFile())) {
                                for (long j = 0; j < readsNumber; j++) {
                                    long bytesToRead = chunkBytesToRead > bufferSize ? bufferSize : chunkBytesToRead;
                                    int bytesRead = in.read(buffer, 0, (int) bytesToRead);
                                    if (-1 == bytesRead) break;
                                    out.write(buffer, 0, bytesRead);
                                    chunkBytesToRead -= bytesRead;
                                    totalBytesToRead -= bytesRead;
                                }
                            }
                            sastApi.uploadArtifacts(i, chunkFile.getFile().toFile(), projectName, partsNumber, uploadId);
                            log("Uploaded part %d of %d", i, partsNumber);
                        }
                    }
                }
            }
        } catch (ApiException e) {
            throw new PtaiServerException("PT AI EE project upload API failed", e);
        } catch (IOException e) {
            throw new PtaiClientException("File operation failed", e);
        } catch (Exception e) {
            throw new PtaiClientException("Temporary file operation failed", e);
        }
    }
}