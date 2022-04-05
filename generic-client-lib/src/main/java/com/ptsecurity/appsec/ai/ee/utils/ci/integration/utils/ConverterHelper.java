package com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils;

import com.google.gson.annotations.SerializedName;
import lombok.SneakyThrows;
import org.apache.commons.lang3.ClassUtils;

import java.lang.reflect.Field;

import static org.joor.Reflect.on;

public class ConverterHelper {
    /**
     * Method hierarchically searches Boolean fields annotated
     * as SerializedName and sets them to false
     * @param object Object instance to init
     */
    @SneakyThrows
    public static void initRemainingSettingsFields(final Object object) {
        if (null == object) return;
        Class<?> c = object.getClass();
        // Iterate through class hierarchy
        while (null != c) {
            // Init fields annotated with @SerializedName
            for (Field field : c.getDeclaredFields()) {
                if (!field.isAnnotationPresent(SerializedName.class)) continue;
                initField(object, field);
            }
            c = c.getSuperclass();
        }
    }

    /**
     * If field is of Boolean type, set its value to false. Iterate
     * through its nested fields otherwise and set them in the same manner
     * @param object Object instance field belongs to
     * @param field Field that value is to be initialized
     */
    @SneakyThrows
    protected static void initField(final Object object, final Field field) {
        if (null == field) return;
        Class<?> c = field.getType();
        if (ClassUtils.isPrimitiveWrapper(c) && Boolean.class.equals(c))
            if (null == on(object).field(field.getName()).get())
                on(object).set(field.getName(), false);
            else
                initRemainingSettingsFields(on(object).field(field.getName()).get());
    }
}
