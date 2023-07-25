package com.ptsecurity.misc.tools.helpers;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;

public class UrlHelper {
    public static boolean checkUrl(final String value) {
        try {
            new URL(value).toURI();
            return true;
        } catch (MalformedURLException e) {
            return false;
        } catch (URISyntaxException e) {
            return false;
        }
    }

}
