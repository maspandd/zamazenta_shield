package com.zamazenta.shield;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.util.Base64;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/** Signing-certificate fingerprints (lower-case SHA-256 hex) for the app and for other packages. */
final class Signers {
    private Signers() {}

    /**
     * Parses a ';' or ',' separated list. Each entry may be a SHA-256 fingerprint in hex
     * (colons optional), a Base64 SHA-256 digest, or a Base64 / PEM DER certificate.
     */
    static Set<String> parseList(String raw) {
        Set<String> out = new LinkedHashSet<>();
        if (raw == null) return out;
        for (String token : raw.split("[;,]")) {
            String entry = token.replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");
            if (entry.isEmpty()) continue;
            String hex = entry.replace(":", "");
            if (hex.matches("[0-9a-fA-F]{64}")) {
                out.add(hex.toLowerCase(Locale.US));
                continue;
            }
            try {
                byte[] bytes = Base64.decode(entry, Base64.DEFAULT);
                out.add(bytes.length == 32 ? toHex(bytes) : sha256(bytes));
            } catch (IllegalArgumentException ignored) {
                // Not Base64; nothing we can match against.
            }
        }
        return out;
    }

    @SuppressWarnings("deprecation")
    static Set<String> fingerprints(PackageManager pm, String packageName) {
        Set<String> out = new LinkedHashSet<>();
        try {
            Signature[] signatures;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES);
                SigningInfo signing = info.signingInfo;
                if (signing == null) return out;
                signatures = signing.hasMultipleSigners()
                        ? signing.getApkContentsSigners()
                        : signing.getSigningCertificateHistory();
            } else {
                signatures = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures;
            }
            if (signatures == null) return out;
            for (Signature signature : signatures) out.add(sha256(signature.toByteArray()));
        } catch (PackageManager.NameNotFoundException | RuntimeException ignored) {
            // Package not visible to us, or the platform refused the query.
        }
        return out;
    }

    static boolean anyMatch(Set<String> actual, Set<String> trusted) {
        return !actual.isEmpty() && !Collections.disjoint(actual, trusted);
    }

    static String sha256(byte[] data) {
        try {
            return toHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format(Locale.US, "%02x", b));
        return sb.toString();
    }
}
