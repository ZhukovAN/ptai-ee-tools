package com.ptsecurity.appsec.ai.ee.utils.ci.integration.base.utils;

import org.apache.commons.codec.digest.DigestUtils;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.file.Files;

import static java.nio.charset.StandardCharsets.UTF_8;

public class TestUtils {
    public static File getFileFromResources(String parentFolder, String fileName) {
        try {
            String path = "/" + parentFolder + "/" + fileName;
            String utfDecodedFilePath = URLDecoder.decode(
                    TestUtils.class.getResource(path).getFile(),
                    UTF_8.toString());
            return new File(utfDecodedFilePath);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getMd5(String data) {
        return DigestUtils.md5Hex(data).toUpperCase();
    }

    public static String getTextFromResources(String parentFolder, String fileName) {
        try {
            File file = getFileFromResources(parentFolder, fileName);
            return new String(Files.readAllBytes(file.toPath()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
