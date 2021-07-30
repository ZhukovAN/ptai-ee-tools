package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.domain.ConnectionSettings;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.exceptions.VersionUnsupportedException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.tasks.*;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.VersionHelper;
import io.github.classgraph.ClassGraph;
import io.github.classgraph.ClassInfoList;
import io.github.classgraph.ScanResult;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Modifier;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.CallHelper.call;
import static org.joor.Reflect.onClass;

@Slf4j
@RequiredArgsConstructor
public class Factory {
    public CheckServerTasks checkServerTasks(@NonNull final AbstractApiClient client) throws GenericException {
        String className = client.getClass().getPackage().getName() + "." + "tasks.CheckServerTasksImpl";
        return onClass(className).create(client).get();
    }

    public ReportsTasks reportsTasks(@NonNull final AbstractApiClient client) throws GenericException {
        String className = client.getClass().getPackage().getName() + "." + "tasks.ReportsTasksImpl";
        return onClass(className).create(client).get();
    }

    public ProjectTasks projectTasks(@NonNull final AbstractApiClient client) throws GenericException {
        String className = client.getClass().getPackage().getName() + "." + "tasks.ProjectTasksImpl";
        return onClass(className).create(client).get();
    }

    public GenericAstTasks genericAstTasks(@NonNull final AbstractApiClient client) throws GenericException {
        String className = client.getClass().getPackage().getName() + "." + "tasks.GenericAstTasksImpl";
        return onClass(className).create(client).get();
    }

    public static List<Class<?>> getAllClientImplementations() {
        // Search for available VersionRange-annotated non-abstract descendants of AbstractApiClient
        log.debug("Scan PT AI server API client implementations");
        Instant start = Instant.now();
        ScanResult scanResult = new ClassGraph()
                .enableClassInfo()
                .enableAnnotationInfo()
                .acceptPackages("com.ptsecurity.appsec")
                .scan();
        ClassInfoList classInfoList = scanResult.getClassesWithAnnotation(VersionRange.class.getName());
        Duration classScanDuration = Duration.between(start, Instant.now());
        log.debug("Scan took {} ns, {} client implementations found", classScanDuration.toNanos(), classInfoList.size());
        return new ArrayList<>(classInfoList.loadClasses());
    }

    @NonNull
    public static AbstractApiClient client(@NonNull final ConnectionSettings connectionSettings) throws GenericException {
        List<Class<?>> clients = getAllClientImplementations();
        for (Class<?> clazz : clients) {
            log.debug("Checking {} class", clazz.getCanonicalName());
            if (!AbstractApiClient.class.isAssignableFrom(clazz)) continue;
            if (Modifier.isAbstract(clazz.getModifiers())) continue;

            AbstractApiClient client = onClass(clazz).create(connectionSettings.validate()).get();
            // Initialize all API clients with URL, timeouts, SSL settings etc.
            client.init();
            log.debug("Class {} instance created", clazz.getCanonicalName());
            try {
                call(client::authenticate, "Authentication failed");
                log.debug("Client authenticated");
                String versionString = call(client::getCurrentApiVersion, "PT AI API version read failed")
                        .get(ServerVersionTasks.Component.AIE);
                if (StringUtils.isEmpty(versionString)) {
                    log.debug("Empty PT AI API version");
                    continue;
                }
                log.debug("PT AI API version string: {}", versionString);
                List<Integer> version = call(
                        () -> Arrays.stream(versionString.split("\\.")).map(Integer::valueOf).collect(Collectors.toList()),
                        "Version string parse failed");
                log.debug("PT AI API version parse complete");
                // Client authenticated, but it doesn't mean anything: need to check if version from server lays in VersionRange
                VersionRange versionRange = clazz.getAnnotation(VersionRange.class);
                // Check if PT AI server API version greater than minimum
                List<Integer> minimumVersion = new ArrayList<>();
                for (int i : versionRange.min()) minimumVersion.add(i);
                if (0 != versionRange.min().length && 1 == VersionHelper.compare(minimumVersion, version)) {
                    log.debug("PT AI server API minimum version constraint violated");
                    continue;
                }
                // Check if PT AI server API version less than maximum
                List<Integer> maximumVersion = new ArrayList<>();
                for (int i : versionRange.max()) maximumVersion.add(i);
                if (0 != versionRange.max().length && 1 == VersionHelper.compare(version, maximumVersion)) {
                    log.debug("PT AI server API maximum version constraint violated");
                    continue;
                }
                return client;
            } catch (GenericException e) {
                log.debug("PT AI server API check failed", e);
            }
        }
        throw GenericException.raise("PT AI server API client create failed", new VersionUnsupportedException());
    }
}
