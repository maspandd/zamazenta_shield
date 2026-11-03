package com.zamazenta.shield;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Small readers for procfs files and Android system properties. */
final class SystemFiles {
    private static final Pattern PROP_LINE = Pattern.compile("^\\[(.+?)]: \\[(.*)]$");
    private static volatile Map<String, String> props;

    private SystemFiles() {}

    static List<String> lines(String path) {
        List<String> out = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = reader.readLine()) != null) out.add(line);
        } catch (IOException | SecurityException ignored) {
            // Missing or unreadable: the check simply finds nothing.
        }
        return out;
    }

    static String firstLine(String path) {
        List<String> all = lines(path);
        return all.isEmpty() ? null : all.get(0).trim();
    }

    /** Value of a "Key:\tvalue" field in /proc/self/status. */
    static String statusField(String key) {
        for (String line : lines("/proc/self/status")) {
            if (line.startsWith(key + ":")) return line.substring(key.length() + 1).trim();
        }
        return null;
    }

    static boolean exists(String path) {
        try {
            return new File(path).exists();
        } catch (SecurityException e) {
            return false;
        }
    }

    /** System property via a single cached {@code getprop} dump (avoids hidden-API reflection). */
    static String prop(String key) {
        String value = allProps().get(key);
        return value == null ? "" : value;
    }

    private static Map<String, String> allProps() {
        Map<String, String> cached = props;
        if (cached != null) return cached;
        synchronized (SystemFiles.class) {
            if (props != null) return props;
            Map<String, String> loaded = new HashMap<>();
            Process process = null;
            try {
                process = new ProcessBuilder("/system/bin/getprop").redirectErrorStream(true).start();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        Matcher m = PROP_LINE.matcher(line);
                        if (m.matches()) loaded.put(m.group(1), m.group(2));
                    }
                }
            } catch (IOException | SecurityException ignored) {
                // Without getprop the property-based checks report nothing.
            } finally {
                if (process != null) process.destroy();
            }
            props = Collections.unmodifiableMap(loaded);
            return props;
        }
    }

    /** Path column of a /proc/self/maps line, or "" for anonymous mappings. */
    static String mapsPath(String line) {
        String[] parts = line.trim().split("\\s+", 6);
        return parts.length == 6 ? parts[5].trim() : "";
    }
}
