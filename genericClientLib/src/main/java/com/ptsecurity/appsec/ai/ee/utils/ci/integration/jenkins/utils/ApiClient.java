package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.Base;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.jenkins.exceptions.JenkinsServerException;
import com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiException;
import org.apache.commons.lang3.StringUtils;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.concurrent.Callable;

/**
 * Generated ApiClient doesn't supports tasks that are inside folders so we need to fix that
 */
public class ApiClient extends com.ptsecurity.appsec.ai.ee.utils.ci.jenkins.server.ApiClient {
    @Override
    public String escapeString(String str) {
        try {
            StringBuilder res = new StringBuilder();
            String[] path = str.split("/");
            for (String item : path)
                res.append(URLEncoder.encode(item, "utf8").replaceAll("\\+", "%20")).append("/");
            res = new StringBuilder(StringUtils.stripEnd(res.toString(), "/"));
            return res.toString();
        } catch (UnsupportedEncodingException e) {
            return str;
        }
    }

    public static String convertJobName(final String jobName) {
        String res = org.apache.commons.lang3.StringUtils.trimToEmpty(jobName);
        res = org.apache.commons.lang3.StringUtils.strip(res, "/");
        res = res.replaceAll("/", "/job/");
        return res;
    }
}