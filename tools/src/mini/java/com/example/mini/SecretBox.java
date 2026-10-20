package com.example.mini;

import java.util.HashMap;
import java.util.Map;

public final class SecretBox {
    public static final String API_BASE = "https://api.example.com/v1/data";
    public static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
    public static final String CONTACT = "analyst@example.com";
    public static final String JWT =
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummySignature";
    public static final String GREETING = "Hello \uD83D\uDE00 \u4F60\u597D";

    private SecretBox() {
    }

    public static Map<String, String> headers(String token) {
        Map<String, String> map = new HashMap<>();
        map.put("Authorization", "Bearer " + token);
        map.put("X-Trace", GREETING);
        return map;
    }

    private native String nativeToken();

    static final class Caf\u00e9 {
        String na\u00efve() {
            return GREETING;
        }
    }

    enum Mode {
        FAST,
        SAFE
    }
}
