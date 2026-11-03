package com.zamazenta.shield;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/** One positive detection: the threat plus the indicators that triggered it. */
final class Detection {
    private static final int MAX_EVIDENCE = 12;

    final Threat threat;
    final List<String> evidence;
    final long timestamp = System.currentTimeMillis();

    Detection(Threat threat, List<String> evidence) {
        List<String> unique = new ArrayList<>(new LinkedHashSet<>(evidence));
        this.threat = threat;
        this.evidence = Collections.unmodifiableList(
                unique.size() > MAX_EVIDENCE ? unique.subList(0, MAX_EVIDENCE) : unique);
    }

    static Detection of(Threat threat, String evidence) {
        return new Detection(threat, Collections.singletonList(evidence));
    }

    static void addIfAny(List<Detection> out, Threat threat, List<String> evidence) {
        if (!evidence.isEmpty()) out.add(new Detection(threat, evidence));
    }

    /** Combines detections of the same threat (e.g. from the Java and native layers) into one. */
    static List<Detection> merge(List<Detection> detections) {
        Map<Threat, List<String>> grouped = new LinkedHashMap<>();
        for (Detection d : detections) {
            List<String> evidence = grouped.get(d.threat);
            if (evidence == null) {
                evidence = new ArrayList<>();
                grouped.put(d.threat, evidence);
            }
            evidence.addAll(d.evidence);
        }
        List<Detection> out = new ArrayList<>();
        for (Map.Entry<Threat, List<String>> entry : grouped.entrySet()) {
            out.add(new Detection(entry.getKey(), entry.getValue()));
        }
        return out;
    }

    JSONObject toJson(String action) {
        JSONObject json = new JSONObject();
        try {
            json.put("code", threat.code);
            json.put("id", threat.id);
            json.put("description", threat.description);
            json.put("action", action);
            json.put("evidence", new JSONArray(evidence));
            json.put("platform", "android");
            json.put("timestamp", timestamp);
        } catch (JSONException ignored) {
            // put() only throws for non-finite numbers; none are used here.
        }
        return json;
    }
}
