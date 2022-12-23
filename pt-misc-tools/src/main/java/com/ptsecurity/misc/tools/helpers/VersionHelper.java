package com.ptsecurity.misc.tools.helpers;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

import static com.ptsecurity.misc.tools.helpers.StringHelper.listToString;

@Slf4j
public class VersionHelper {
    /**
     * Method compares two integer arrays representing versions
     * @param versionA First version to compare
     * @param versionB Second version to compare
     * @return -1 if versionA precedes (less than) versionB,
     * 0 - if those are equal and 1 - if versionA follows (greater than) versionB
     */
    public static int compare(@NonNull final List<Integer> versionA, @NonNull final List<Integer> versionB) {
        Integer res = null;
        int commonIndices = Math.min(versionA.size(), versionB.size());
        for (int i = 0; i < commonIndices; i++) {
            if (versionA.get(i).equals(versionB.get(i))) continue;
            res = Integer.compare(versionA.get(i), versionB.get(i));
            break;
        }
        // If we got this far then all the common indices are identical, so
        // whichever version is longer must be more recent
        if (null == res) res = Integer.compare(versionA.size(), versionB.size());
        log.trace("Compare versions: {} {} {}",
                listToVersion(versionA),
                0 == res ? "=" : -1 == res ? "<" : ">",
                listToVersion(versionB));
        return res;
    }

    protected static String listToVersion(@NonNull final List<Integer> version) {
        return listToString(".", version);
    }
}
