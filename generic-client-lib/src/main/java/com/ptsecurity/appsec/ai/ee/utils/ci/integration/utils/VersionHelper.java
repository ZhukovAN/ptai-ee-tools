package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import lombok.NonNull;

import java.util.List;

public class VersionHelper {
    /**
     * Method compares two integer arrays representing versions
     * @param versionA First version to compare
     * @param versionB Second version to compare
     * @return -1 if versionA precedes (less than) versionB,
     * 0 - if those are equal and 1 - if versionA follows (greater than) versionB
     */
    public static int compare(@NonNull final List<Integer> versionA, @NonNull final List<Integer> versionB) {
        int commonIndices = Math.min(versionA.size(), versionB.size());
        for (int i = 0; i < commonIndices; i++) {
            if (versionA.get(i) != versionB.get(i))
                return Integer.compare(versionA.get(i), versionB.get(i));
        }
        // If we got this far then all the common indices are identical, so
        // whichever version is longer must be more recent
        return Integer.compare(versionA.size(), versionB.size());
    }
}
