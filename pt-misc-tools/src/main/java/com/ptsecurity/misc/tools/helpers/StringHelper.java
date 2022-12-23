package com.ptsecurity.misc.tools.helpers;

import lombok.NonNull;

import java.util.List;
import java.util.stream.Collectors;

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

    @NonNull
    public static String arrayAsString(final String[] values) {
        if (null == values || 0 == values.length) return "[<empty>]";
        return "[".concat(String.join(", ", values)).concat("]");
    }

    @NonNull
    public static String listToString(final List<Integer> values) {
        return listToString(", ", values);
    }

    public static String listToString(@NonNull final String delimiter, final List<Integer> values) {
        if (null == values || 0 == values.size()) return "<empty>";
        return values.stream().map(Object::toString).collect(Collectors.joining(delimiter));
    }
}
