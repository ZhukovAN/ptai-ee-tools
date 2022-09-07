package com.ptsecurity.appsec.tools.jenkins.dependencies.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.io.InputStream;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class PluginVersions {
    @NonNull
    protected String generationTimestamp;

    @NonNull
    protected Map<String, Map<String, Plugin>> plugins;

    /**
     * Map that bounds plugin name and version to {@link Plugin} instance
     */
    @JsonIgnore
    protected final Map<Pair<String, String>, Plugin> pluginVersionsMap = new HashMap<>();

    public void process() {
        pluginVersionsMap.clear();
        for (Map.Entry<String, Map<String, Plugin>> pluginVersionsEntry : plugins.entrySet()) {
            for (Map.Entry<String, Plugin> pluginEntry : pluginVersionsEntry.getValue().entrySet())
                pluginVersionsMap.put(new ImmutablePair<>(pluginEntry.getValue().getName(), pluginEntry.getValue().getVersion()), pluginEntry.getValue());
        }
    }

    /**
     * Compare two version strings
     * @param a First version string to compare
     * @param b Second version string to compare
     * @return Returns -1 if version "a" is before "b", 0 if those are equal and 1 if "a" is after "b"
     */
    public static int compareVersion(@NonNull final String a, @NonNull final String b) {
        String[] versionA = a.split("[-.]");
        String[] versionB = b.split("[-.]");
        int commonIndices = Math.min(versionA.length, versionB.length);
        for (int i = 0; i < commonIndices; ++i) {
            try {
                int numberA = Integer.parseInt(versionA[i]);
                int numberB = Integer.parseInt(versionB[i]);
                if (numberA != numberB) return Integer.compare(numberA, numberB);
            } catch (NumberFormatException e) {
                if (!versionA[i].equals(versionB[i])) return versionA[i].compareTo(versionB[i]);
            }
        }
        // If we got this far then all the common indices are identical, so whichever version is longer must be more recent
        return Integer.compare(versionA.length, versionB.length);
    }

    /**
     * Method searches plugin-versions.json (@link https://updates.jenkins-ci.org/current/plugin-versions.json})
     * for a most recent plugin version that supports required Jenkins version. Then it resolves all the dependencies
     * including transitive ones, checks dependencies for a duplicates that differ in a version only, removes
     * not-the-latest-version dependencies and returns plain set of plugins that are to be deployed to Jenkins server
     * @param name Plugin name
     * @param jenkinsVersion Jenkins version that plugin must support
     * @return Set of plugins (including one defined by {@code name} parameter and dependent ones) that are to be installed
     */
    public Set<Plugin> requiredPlugins(@NonNull final String name, @NonNull final String jenkinsVersion) {
        // TODO: Try to implement "most recent version" approach i.e. build dependency tree using most recent HPIs versions that fit Jenkins version instead of manifest-defined ones
        log.debug("Collect {} plugin requirements for Jenkins {}", name, jenkinsVersion);
        log.trace("Get all {} plugin versions and sort those descendant", name);
        @NonNull Map<String, Plugin> pluginVersionsMap = plugins.get(name);
        List<String> versions = new ArrayList<>(pluginVersionsMap.keySet());
        versions.sort((String v1, String v2) -> - compareVersion(v1, v2));
        for (String version : versions) {
            Plugin plugin = pluginVersionsMap.get(version);
            log.trace("Process {} plugin", plugin);
            if (1 == compareVersion(plugin.getRequiredCore(), jenkinsVersion)) {
                log.trace("Skip {} version as ir requires Jenkins {}", version, plugin.getVersion());
                continue;
            }
            try {
                PluginTreeNode rootPluginNode = new PluginTreeNode(plugin);
                rootPluginNode.setMostRecentVersion(true);
                collectPluginDependencies(plugin, jenkinsVersion, rootPluginNode);
                log.trace("{} plugin dependencies resolved", plugin);
                // As there may be plugin duplicates let's collect unique plugin names and remove subtrees that aren't the most recent ones
                List<PluginTreeNode> childNodes = new ArrayList<>();
                rootPluginNode.collectChildNodes(childNodes, (n) -> true);
                Map<String, TreeSet<String>> childNodesByName = childNodes
                        .stream()
                        .collect(
                                Collectors.groupingBy(
                                        PluginTreeNode::getName,
                                        Collectors.mapping(PluginTreeNode::getVersion, Collectors.toCollection(() -> new TreeSet<>(PluginVersions::compareVersion)))));
                // Iterate through plugin names and mark most recent plugin versions in dependency tree
                for (String pluginName : childNodesByName.keySet()) {
                    @NonNull TreeSet<String> pluginVersions = childNodesByName.get(pluginName);
                    if (0 == pluginVersions.size()) continue;
                    Iterator<String> iterator = pluginVersions.descendingIterator();
                    // Get most recent plugin version...
                    String mostRecentVersionNumber = iterator.next();
                    rootPluginNode.setAsMostRecentVersion(pluginName, mostRecentVersionNumber);
                }
                childNodes.clear();
                rootPluginNode.collectChildNodes(childNodes, PluginTreeNode::isMostRecentVersion);

                return childNodes.stream().map(PluginTreeNode::getPlugin).collect(Collectors.toSet());
            } catch (Exception e) {
                log.trace(e.getMessage());
            }
        }
        return null;
    }

    public Set<Plugin> requiredPlugins(@NonNull final Set<String> names, @NonNull final String jenkinsVersion) {
        Plugin dummyPlugin = new Plugin();
        dummyPlugin.setName(UUID.randomUUID().toString());
        dummyPlugin.setVersion(UUID.randomUUID().toString());
        for (String name : names) {
            log.debug("Collect {} plugin requirements for Jenkins {}", name, jenkinsVersion);
            log.trace("Get all {} plugin versions and sort those descendant", name);
            @NonNull Map<String, Plugin> pluginVersionsMap = plugins.get(name);
            List<String> versions = new ArrayList<>(pluginVersionsMap.keySet());
            versions.sort((String v1, String v2) -> - compareVersion(v1, v2));
            for (String version : versions) {
                Plugin plugin = pluginVersionsMap.get(version);
                log.trace("Process {} plugin", plugin);
                if (1 == compareVersion(plugin.getRequiredCore(), jenkinsVersion)) {
                    log.trace("Skip {} version as ir requires Jenkins {}", version, plugin.getVersion());
                    continue;
                }
                dummyPlugin.getDependencies().add(new Plugin.Dependency(plugin.getName(), false, plugin.getVersion()));
                break;
            }
        }
        try {
            PluginTreeNode rootPluginNode = new PluginTreeNode(dummyPlugin);
            rootPluginNode.setMostRecentVersion(true);
            collectPluginDependencies(dummyPlugin, jenkinsVersion, rootPluginNode);
            log.trace("{} plugin dependencies resolved", rootPluginNode);
            // As there may be plugin duplicates let's collect unique plugin names and remove subtrees that aren't the most recent ones
            List<PluginTreeNode> childNodes = new ArrayList<>();
            rootPluginNode.collectChildNodes(childNodes, (n) -> true);
            childNodes.removeIf(pluginTreeNode -> dummyPlugin.getName().equals(pluginTreeNode.getName()));
            Map<String, TreeSet<String>> childNodesByName = childNodes
                    .stream()
                    .collect(
                            Collectors.groupingBy(
                                    PluginTreeNode::getName,
                                    Collectors.mapping(PluginTreeNode::getVersion, Collectors.toCollection(() -> new TreeSet<>(PluginVersions::compareVersion)))));
            // Iterate through plugin names and mark most recent plugin versions in dependency tree
            for (String pluginName : childNodesByName.keySet()) {
                @NonNull TreeSet<String> pluginVersions = childNodesByName.get(pluginName);
                if (0 == pluginVersions.size()) continue;
                Iterator<String> iterator = pluginVersions.descendingIterator();
                // Get most recent plugin version...
                String mostRecentVersionNumber = iterator.next();
                rootPluginNode.setAsMostRecentVersion(pluginName, mostRecentVersionNumber);
            }
            childNodes.clear();
            rootPluginNode.collectChildNodes(childNodes, PluginTreeNode::isMostRecentVersion);

            return childNodes
                    .stream()
                    .filter(n -> !dummyPlugin.getName().equals(n.getName()))
                    .map(PluginTreeNode::getPlugin)
                    .collect(Collectors.toSet());
        } catch (Exception e) {
            log.trace(e.getMessage());
        }
        return null;
    }

    @Getter
    @Setter
    @ToString
    protected static class PluginTreeNode {
        @NonNull
        protected final String name;
        @NonNull
        protected final String version;
        @NonNull
        @ToString.Exclude
        protected final List<PluginTreeNode> children = new ArrayList<>();
        @NonNull
        @ToString.Exclude
        protected final Plugin plugin;

        protected boolean mostRecentVersion = false;

        public PluginTreeNode(@NonNull final Plugin plugin) {
            this.plugin = plugin;
            this.name = plugin.getName();
            this.version = plugin.getVersion();
        }

        protected void collectChildNodes(@NonNull final List<PluginTreeNode> nodes, @NonNull final Predicate<PluginTreeNode> filter) {
            collectChildNodes(this, nodes, filter);
        }

        protected void collectChildNodes(@NonNull final PluginTreeNode node, @NonNull final List<PluginTreeNode> nodes, @NonNull final Predicate<PluginTreeNode> filter) {
            if (!filter.test(node)) return;
            nodes.add(node);
            for (PluginTreeNode child : node.getChildren())
                collectChildNodes(child, nodes, filter);
        }

        public void setAsMostRecentVersion(@NonNull final String name, @NonNull final String version) {
            setAsMostRecentVersion(this, name, version);
        }

        public void setAsMostRecentVersion(@NonNull final PluginTreeNode tree, @NonNull final String name, @NonNull final String version) {
            if (name.equals(tree.getName()) && version.equals(tree.getVersion()))
                tree.setMostRecentVersion(true);
            for (PluginTreeNode child : tree.getChildren())
                setAsMostRecentVersion(child, name, version);
        }
    }

    protected void collectPluginDependencies(@NonNull final Plugin plugin, @NonNull final String jenkinsVersion, @NonNull final PluginTreeNode parentPlugin) throws Exception {
        if (null == plugin.getDependencies()) return;
        for (Plugin.Dependency dependency : plugin.getDependencies()) {
            // Line uncommented as if other plugin also uses this dependency as arbitrary
            // and dependency version less than required optional one then this plugin will
            // fail to load despite dependency's "optional" attribute
            // if (dependency.isOptional()) continue;
            final Plugin requiredPlugin = pluginVersionsMap.get(new ImmutablePair<>(dependency.getName(), dependency.getVersion()));
            if (null == requiredPlugin) {
                log.warn("No plugin found for {} dependency", dependency);
                continue;
            }
            // Terminate plugin dependencies processing if there's unsupported Jenkins version
            if (1 == compareVersion(requiredPlugin.getRequiredCore(), jenkinsVersion))
                throw new Exception("Plugin " + requiredPlugin + " doesn't supports Jenkins " + jenkinsVersion);
            // Add plugin to dependency tree
            PluginTreeNode childPluginNode = new PluginTreeNode(requiredPlugin);
            parentPlugin.getChildren().add(childPluginNode);
            collectPluginDependencies(requiredPlugin, jenkinsVersion, childPluginNode);
        }
    }

    @SneakyThrows
    public static PluginVersions load(@NonNull final InputStream stream) {
        // Create IssuesModel deserializer
        ObjectMapper mapper = new ObjectMapper();
        // Need this as JSONs like aiproj settings may contain comments
        mapper.enable(JsonParser.Feature.ALLOW_COMMENTS);
        // Need this as JSON report contains "Descriptions" while IssuesModel have "descriptions"
        mapper.enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES);
        mapper.enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS);
        // Need this as JSON may contain fields that are missing from model
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        PluginVersions pluginVersions = mapper.readValue(stream, PluginVersions.class);
        pluginVersions.process();
        return pluginVersions;
    }

}
