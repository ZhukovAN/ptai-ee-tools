package com.ptsecurity.misc.tools.helpers;

import lombok.NonNull;
import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Hex;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;

public class HashHelper {
    @SneakyThrows
    public static String md5(@NonNull final String value) {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(value.getBytes());
        return Hex.encodeHexString(md5.digest()).toUpperCase();
    }
}
