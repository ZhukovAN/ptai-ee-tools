package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.SneakyThrows;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.ClassUtils;
import org.joor.Reflect;
import org.parboiled.common.StringUtils;

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.UUID;

public class BaseJsonChartDataModel {
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
                Object value = Reflect.on(object).field(field.getName()).get();
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
        else if (c.equals(UUID.class))
            return value.toString();
        else if (ClassUtils.isPrimitiveOrWrapper(c))
            return value;
        else if (c.isEnum())
            return value.toString();
        else
            return convertObject(value);
    }

    public static JSONArray convertCollection(final Object collection) {
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
