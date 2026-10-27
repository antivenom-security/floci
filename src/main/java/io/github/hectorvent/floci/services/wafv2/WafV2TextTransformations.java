package io.github.hectorvent.floci.services.wafv2;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Deque;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AWS WAF text transformations ("Using text transformations in AWS WAF"), on a string that holds one
 * byte per char (ISO-8859-1), so binary results such as {@code MD5} survive.
 */
final class WafV2TextTransformations {

    private static final String SPACE = "[ \\t\\n\\u000B\\f\\r]";
    private static final Pattern ENTITY = Pattern.compile("&(?:#[xX]([0-9a-fA-F]{1,6})|#([0-9]{1,7})|([A-Za-z]+));?");
    private static final Map<String, String> ENTITIES = Map.ofEntries(
            Map.entry("quot", "\""), Map.entry("amp", "&"), Map.entry("lt", "<"), Map.entry("gt", ">"),
            Map.entry("nbsp", "\u00A0"), Map.entry("nonbreakingspace", "\u00A0"), Map.entry("newline", "\n"),
            Map.entry("tab", "\t"), Map.entry("lcub", "{"), Map.entry("lbrace", "{"), Map.entry("verbar", "|"),
            Map.entry("vert", "|"), Map.entry("verticalline", "|"), Map.entry("rcub", "}"), Map.entry("rbrace", "}"),
            Map.entry("excl", "!"), Map.entry("num", "#"), Map.entry("dollar", "$"), Map.entry("percent", "%"),
            Map.entry("percnt", "%"), Map.entry("apos", "'"), Map.entry("lpar", "("), Map.entry("rpar", ")"),
            Map.entry("ast", "*"), Map.entry("midast", "*"), Map.entry("plus", "+"), Map.entry("comma", ","),
            Map.entry("period", "."), Map.entry("sol", "/"), Map.entry("colon", ":"), Map.entry("semi", ";"),
            Map.entry("equals", "="), Map.entry("quest", "?"), Map.entry("tilde", "~"),
            Map.entry("diacriticaltilde", "~"), Map.entry("minus", "-"), Map.entry("lsqb", "["),
            Map.entry("lbrack", "["), Map.entry("bsol", "\\"), Map.entry("rsqb", "]"), Map.entry("rbrack", "]"),
            Map.entry("hat", "^"), Map.entry("lowbar", "_"), Map.entry("underbar", "_"), Map.entry("grave", "`"),
            Map.entry("diacriticalgrave", "`"));

    private WafV2TextTransformations() {}

    /** The transformed value, or null for a transformation Floci does not implement. */
    static String apply(String type, String value) {
        return switch (type) {
            case "NONE" -> value;
            case "LOWERCASE" -> asciiCase(value, true);
            case "UPPERCASE" -> asciiCase(value, false);
            case "URL_DECODE" -> urlDecode(value);
            case "HTML_ENTITY_DECODE" -> htmlEntityDecode(value);
            case "COMPRESS_WHITE_SPACE" -> value.replaceAll("[\\t\\n\\u000B\\f\\r\\u00A0]", " ")
                    .replaceAll(" {2,}", " ");
            case "REMOVE_WHITESPACE" -> value.replaceAll(SPACE, "");
            case "TRIM" -> value.replaceAll("^" + SPACE + "+|" + SPACE + "+$", "");
            case "TRIM_LEFT" -> value.replaceAll("^" + SPACE + "+", "");
            case "TRIM_RIGHT" -> value.replaceAll(SPACE + "+$", "");
            case "REMOVE_NULLS" -> value.replace("\0", "");
            case "REPLACE_NULLS" -> value.replace('\0', ' ');
            case "REMOVE_COMMENTS_CHAR" -> value.replaceAll("/\\*|\\*/|--|#", "");
            case "REPLACE_COMMENTS" -> value.replaceAll("(?s)/\\*.*?(?:\\*/|$)", " ");
            case "CMD_LINE" -> asciiCase(value.replaceAll("[\\\\\"'^]", "").replaceAll("[,;]", " ")
                    .replaceAll(" {2,}", " ").replaceAll(" +(?=[/(])", ""), true);
            case "CMD_LINE_UNIX" -> asciiCase(value.replaceAll("[\\\\\"']", "")
                    .replaceAll("[\\t\\n\\r\\u000B\\f]", " ").replaceAll(" {2,}", " ").strip(), true);
            case "NORMALIZE_PATH" -> normalizePath(value);
            case "NORMALIZE_PATH_WIN" -> normalizePath(value.replace('\\', '/'));
            case "BASE64_DECODE" -> decoded(() -> Base64.getDecoder().decode(value), value);
            case "HEX_DECODE" -> decoded(() -> HexFormat.of().parseHex(value), value);
            case "MD5" -> digest("MD5", value);
            case "SHA256" -> digest("SHA-256", value);
            default -> null;
        };
    }

    private static String asciiCase(String value, boolean lower) {
        StringBuilder out = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            out.append(lower && c >= 'A' && c <= 'Z' ? (char) (c + 32)
                    : !lower && c >= 'a' && c <= 'z' ? (char) (c - 32) : c);
        }
        return out.toString();
    }

    private static String urlDecode(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '%' && i + 2 < value.length() && HexFormat.isHexDigit(value.charAt(i + 1))
                    && HexFormat.isHexDigit(value.charAt(i + 2))) {
                out.append((char) HexFormat.fromHexDigits(value, i + 1, i + 3));
                i += 2;
            } else {
                out.append(c == '+' ? ' ' : c);
            }
        }
        return out.toString();
    }

    private static String htmlEntityDecode(String value) {
        Matcher matcher = ENTITY.matcher(value);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            String replacement;
            if (matcher.group(3) != null) {
                replacement = ENTITIES.getOrDefault(matcher.group(3).toLowerCase(Locale.ROOT), matcher.group());
            } else {
                int code = matcher.group(1) != null ? Integer.parseInt(matcher.group(1), 16)
                        : Integer.parseInt(matcher.group(2));
                replacement = String.valueOf((char) (code & 0xFF));
            }
            matcher.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        return matcher.appendTail(out).toString();
    }

    /** Removes repeated slashes and {@code .} segments, and resolves {@code ..} past the first segment. */
    private static String normalizePath(String value) {
        String[] segments = value.replaceAll("/{2,}", "/").split("/", -1);
        Deque<String> kept = new ArrayDeque<>();
        for (int i = 0; i < segments.length; i++) {
            String segment = segments[i];
            if (".".equals(segment) && i > 0) {
                continue;
            }
            if ("..".equals(segment) && !kept.isEmpty() && !kept.peekLast().isEmpty()
                    && !"..".equals(kept.peekLast())) {
                kept.pollLast();
                continue;
            }
            kept.addLast(segment);
        }
        return String.join("/", kept);
    }

    private static String decoded(Supplier<byte[]> decoder, String value) {
        try {
            return new String(decoder.get(), StandardCharsets.ISO_8859_1);
        } catch (IllegalArgumentException e) {
            return value;
        }
    }

    private static String digest(String algorithm, String value) {
        try {
            return new String(MessageDigest.getInstance(algorithm).digest(value.getBytes(StandardCharsets.ISO_8859_1)),
                    StandardCharsets.ISO_8859_1);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
