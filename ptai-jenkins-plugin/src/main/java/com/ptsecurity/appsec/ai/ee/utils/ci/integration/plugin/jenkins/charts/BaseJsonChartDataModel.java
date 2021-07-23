package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue.Level;
import lombok.SneakyThrows;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.ClassUtils;
import org.parboiled.common.StringUtils;

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class BaseJsonChartDataModel {
    public static int COLOR_HIGH = 0xf57962;
    public static int COLOR_MEDIUM = 0xf9ad37;
    public static int COLOR_LOW = 0x66cc99;
    public static int COLOR_POTENTIAL = 0x8cb5e1;

    protected static final Map<Level, StackedAreaChartDataModel.Series.ItemStyle> ITEM_STYLE_MAP = new HashMap<>();

    protected static final Map<Level, StackedAreaChartDataModel.Series.ItemStyle> AREA_STYLE_MAP = new HashMap<>();

    static {
        ITEM_STYLE_MAP.put(Level.HIGH, StackedAreaChartDataModel.Series.ItemStyle.builder().color("#" + Integer.toHexString(COLOR_HIGH)).build());
        ITEM_STYLE_MAP.put(Level.MEDIUM, StackedAreaChartDataModel.Series.ItemStyle.builder().color("#" + Integer.toHexString(COLOR_MEDIUM)).build());
        ITEM_STYLE_MAP.put(Level.LOW, StackedAreaChartDataModel.Series.ItemStyle.builder().color("#" + Integer.toHexString(COLOR_LOW)).build());
        ITEM_STYLE_MAP.put(Level.POTENTIAL, StackedAreaChartDataModel.Series.ItemStyle.builder().color("#" + Integer.toHexString(COLOR_POTENTIAL)).build());
    }

    @SneakyThrows
    public static JSONObject convertObject(final Object object) {
        if (null == object) return null;
        JSONObject res = new JSONObject();
        Class<?> c = object.getClass();
        // Iterate through class hierarchy
        while (null != c) {
            // Add fields
            for (Field field : c.getDeclaredFields()) {
                if (!field.isAnnotationPresent(JsonProperty.class)) continue;
                JsonProperty jsonProperty = field.getAnnotation(JsonProperty.class);
                String jsonFieldName = StringUtils.isEmpty(jsonProperty.value())
                        ? field.getName() : jsonProperty.value();
                Object value = field.get(object);
                if (null == value) continue;

                Object jsonValue = convertValue(value);
                if (null != jsonValue) res.put(jsonFieldName, jsonValue);
            }
            c = c.getSuperclass();
        }
        return res;
    }

    protected static Object convertValue(final Object value) {
        if (null == value) return null;
        Class<?> c = value.getClass();
        if (Collection.class.isAssignableFrom(c))
            return convertCollection(value);
        else if (c.isArray())
            return convertCollection(value);
        else if (c.equals(String.class))
            return value;
        else if (ClassUtils.isPrimitiveOrWrapper(c))
            return value;
        else if (c.isEnum())
            return value.toString();
        else
            return convertObject(value);
    }

    protected static JSONArray convertCollection(final Object collection) {
        if (null == collection) return null;

        JSONArray res = new JSONArray();
        Class<?> c = collection.getClass();
        if (c.isArray()) {
            Object[] items = (Object[]) collection;
            for (Object item : items) res.add(convertValue(item));
        } else if (Collection.class.isAssignableFrom(c)) {
            Collection<Object> items = (Collection<Object>) collection;
            for (Object item : items) res.add(convertValue(item));
        }
        return res;
    }
}
