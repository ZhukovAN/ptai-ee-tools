package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiClient;
import org.apache.commons.lang.StringUtils;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

/**
 * Generated ApiClient doesn't supports tasks that are inside folders so we need to fix that
 */
public class PtaiJenkinsApiClient extends ApiClient {
    @Override
    public String escapeString(String str) {
        try {
            StringBuilder l_strRes = new StringBuilder();
            String[] l_strPath = str.split("/");
            for (String l_strPathItem : l_strPath)
                l_strRes.append(URLEncoder.encode(l_strPathItem, "utf8").replaceAll("\\+", "%20")).append("/");
            l_strRes = new StringBuilder(StringUtils.stripEnd(l_strRes.toString(), "/"));
            return l_strRes.toString();
        } catch (UnsupportedEncodingException e) {
            return str;
        }
    }

    public static String convertJobName(final String jobName) {
        String l_strRes = org.apache.commons.lang3.StringUtils.trimToEmpty(jobName);
        l_strRes = org.apache.commons.lang3.StringUtils.strip(l_strRes, "/");
        l_strRes = l_strRes.replaceAll("/", "/job/");
        return l_strRes;
    }
}