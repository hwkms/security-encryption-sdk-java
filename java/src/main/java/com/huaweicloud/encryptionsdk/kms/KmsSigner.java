package com.huaweicloud.encryptionsdk.kms;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.TreeMap;

/**
 * SDK-HMAC-SHA256 签名工具，替代 com.huawei.apigateway:java-sdk-core 的 Client.sign()。
 *
 * 签名流程：
 * 1. 构造规范化请求 (CanonicalRequest)
 * 2. 构造待签字符串 (StringToSign)
 * 3. HMAC-SHA256 计算签名
 * 4. 拼装 Authorization 头
 */
public class KmsSigner {

    private static final String ALGORITHM = "SDK-HMAC-SHA256";
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final String SHA_256 = "SHA-256";
    private static final String DATE_FORMAT = "yyyyMMdd'T'HHmmss'Z'";
    private static final String HEADER_HOST = "host";
    private static final String HEADER_X_SDK_DATE = "x-sdk-date";
    private static final String HEADER_CONTENT_TYPE = "content-type";
    private static final String HEADER_X_SECURITY_TOKEN = "x-security-token";

    private final String ak;
    private final String sk;
    private final String securityToken;

    public KmsSigner(String ak, String sk, String securityToken) {
        this.ak = ak;
        this.sk = sk;
        this.securityToken = securityToken;
    }

    /**
     * 对请求进行签名，返回需要设置的请求头。
     *
     * @param method     HTTP 方法 (GET/POST/PUT/DELETE)
     * @param url        完整 URL (如 https://kms.cn-north-7.myhuaweicloud.com/v1.0/projectId/kms/create-datakey)
     * @param body       请求体 (JSON 字符串)，GET 请求为 null
     * @param contentType Content-Type 头
     * @return 需要设置到 HTTP 请求上的头 Map (key 小写)
     */
    public Map<String, String> sign(String method, String url, String body, String contentType) {
        URI uri = URI.create(url);
        String host = uri.getHost();
        String path = uri.getPath();
        String queryString = uri.getQuery() != null ? uri.getQuery() : "";

        // 时间戳
        java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat(DATE_FORMAT);
        sdf.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        String dateTime = sdf.format(new java.util.Date());

        // 构造 headers（按字典序）
        TreeMap<String, String> headers = new TreeMap<>();
        headers.put(HEADER_HOST, host);
        headers.put(HEADER_X_SDK_DATE, dateTime);
        if (contentType != null) {
            headers.put(HEADER_CONTENT_TYPE, contentType);
        }
        if (securityToken != null && !securityToken.isEmpty()) {
            headers.put(HEADER_X_SECURITY_TOKEN, securityToken);
        }

        // 第 1 步：构造 CanonicalRequest
        String canonicalHeaders = buildCanonicalHeaders(headers);
        String signedHeaders = buildSignedHeaders(headers);
        String hashedPayload = sha256Hex(body != null ? body : "");

        // CanonicalURI：末尾必须加 /
        String canonicalPath = path;
        if (!canonicalPath.endsWith("/")) {
            canonicalPath = canonicalPath + "/";
        }

        String canonicalRequest = method.toUpperCase(java.util.Locale.ROOT) + "\n" +
                canonicalPath + "\n" +
                canonicalQueryString(queryString) + "\n" +
                canonicalHeaders + "\n" +
                signedHeaders + "\n" +
                hashedPayload;


        // 第 2 步：构造 StringToSign
        String hashedCanonicalRequest = sha256Hex(canonicalRequest);
        String stringToSign = ALGORITHM + "\n" + dateTime + "\n" + hashedCanonicalRequest;

        // 第 3 步：计算签名（十六进制编码，不是 Base64）
        String signature = hmacSha256Hex(sk, stringToSign);

        // 第 4 步：构造 Authorization 头
        String authorization = ALGORITHM + " Access=" + ak +
                ", SignedHeaders=" + signedHeaders +
                ", Signature=" + signature;

        // 返回需要设置的头
        TreeMap<String, String> result = new TreeMap<>();
        result.put(HEADER_HOST, host);
        result.put(HEADER_X_SDK_DATE, dateTime);
        if (contentType != null) {
            result.put(HEADER_CONTENT_TYPE, contentType);
        }
        if (securityToken != null && !securityToken.isEmpty()) {
            result.put(HEADER_X_SECURITY_TOKEN, securityToken);
        }
        result.put("authorization", authorization);

        return result;
    }

    /**
     * 构造 CanonicalHeaders：每个头格式为 "key:value\n"，按 key 字典序排列。
     */
    private String buildCanonicalHeaders(TreeMap<String, String> headers) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            sb.append(entry.getKey()).append(":").append(entry.getValue()).append("\n");
        }
        return sb.toString();
    }

    /**
     * 构造 SignedHeaders：头名称按字典序排列，分号分隔。
     */
    private String buildSignedHeaders(TreeMap<String, String> headers) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (String key : headers.keySet()) {
            if (!first) sb.append(";");
            sb.append(key);
            first = false;
        }
        return sb.toString();
    }

    /**
     * 构造 CanonicalQueryString：查询参数按 key 字典序排列，URL 编码。
     */
    private String canonicalQueryString(String queryString) {
        if (queryString == null || queryString.isEmpty()) {
            return "";
        }
        TreeMap<String, String> params = new TreeMap<>();
        String[] pairs = queryString.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                String key = pair.substring(0, idx);
                String value = pair.substring(idx + 1);
                params.put(key, value);
            } else {
                params.put(pair, "");
            }
        }
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (!first) sb.append("&");
            sb.append(entry.getKey());
            if (!entry.getValue().isEmpty()) {
                sb.append("=").append(entry.getValue());
            }
            first = false;
        }
        return sb.toString();
    }

    /**
     * SHA-256 哈希，返回十六进制小写字符串。
     */
    private String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256);
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 hash failed", e);
        }
    }

    /**
     * HMAC-SHA256 签名，返回十六进制小写字符串（与华为云签名 SDK 一致，不是 Base64）。
     */
    private String hmacSha256Hex(String key, String data) {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            SecretKeySpec secretKeySpec = new SecretKeySpec(
                    key.getBytes(StandardCharsets.UTF_8), HMAC_SHA256);
            mac.init(secretKeySpec);
            byte[] signature = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(signature);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 sign failed", e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
