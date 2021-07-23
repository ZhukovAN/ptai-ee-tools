package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import lombok.NonNull;

import java.util.List;

public class StringHelper {
    @NonNull
    public static String joinListGrammatically(@NonNull final List<String> list) {
        if (list.isEmpty()) return "";
        return list.size() > 1
                ? String.join(", ", list.subList(0, list.size() - 1))
                .concat(" and ")
                .concat(list.get(list.size() - 1))
                : list.get(0);
    }
}
