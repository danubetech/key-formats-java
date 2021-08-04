package com.danubetech.keyformats.jose;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public class JWK {
    private String kid;
    private String use;
    private String kty;
    private String crv;
    private String x;
    private String y;
    private String d;

    public JWK() {
    }

    /*
     * Serialization
     */

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static JWK fromJson(String json) throws IOException {
        return objectMapper.readValue(json, JWK.class);
    }

    public static JWK fromJson(Reader reader) throws IOException {
        return objectMapper.readValue(reader, JWK.class);
    }

    public static JWK fromMap(Map<String, Object> map) throws IOException {
        return objectMapper.convertValue(map, JWK.class);
    }

    public Map<String, Object> toMap() {
        return objectMapper.convertValue(this, LinkedHashMap.class);
    }

    public String toJson() {
        try {
            return objectMapper.writeValueAsString(this);
        } catch (JsonProcessingException ex) {
            throw new RuntimeException("Cannot write JSON: " + ex.getMessage(), ex);
        }
    }

    @Deprecated
    public static JWK parse(Map<String, Object> json) {
        return objectMapper.convertValue(json, JWK.class);
    }

    @Deprecated
    public static JWK parse(String string) throws IOException {
        return objectMapper.readValue(new StringReader(string), JWK.class);
    }

    @Deprecated
    public String toJSONString() throws JsonProcessingException {
        return objectMapper.writeValueAsString(this);
    }

    /*
     * Getters and setters
     */

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public String getUse() {
        return use;
    }

    public void setUse(String use) {
        this.use = use;
    }

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = kty;
    }

    public String getCrv() {
        return crv;
    }

    public void setCrv(String crv) {
        this.crv = crv;
    }

    public String getX() {
        return x;
    }

    @JsonIgnore
    public byte[] getXdecoded() {
        String x = this.getX();
        return x != null ? Base64.decodeBase64(x) : null;
    }

    public void setX(String x) {
        this.x = x;
    }

    public String getY() {
        return y;
    }

    @JsonIgnore
    public byte[] getYdecoded() {
        String y = this.getY();
        return y != null ? Base64.decodeBase64(y) : null;
    }

    public void setY(String y) {
        this.y = y;
    }

    public String getD() {
        return d;
    }

    public void setD(String d) {
        this.d = d;
    }

    @JsonIgnore
    public byte[] getDdecoded() {
        String d = this.getD();
        return d != null ? Base64.decodeBase64(d) : null;
    }

    /*
     * Object methods
     */

    @Override
    public String toString() {
        return "JWK{" +
                "kid='" + kid + '\'' +
                ", use='" + use + '\'' +
                ", kty='" + kty + '\'' +
                ", crv='" + crv + '\'' +
                ", x='" + x + '\'' +
                ", y='" + y + '\'' +
                ", d='" + d + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JWK jwk = (JWK) o;
        return Objects.equals(kid, jwk.kid) && Objects.equals(use, jwk.use) && Objects.equals(kty, jwk.kty) && Objects.equals(crv, jwk.crv) && Objects.equals(x, jwk.x) && Objects.equals(y, jwk.y) && Objects.equals(d, jwk.d);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kid, use, kty, crv, x, y, d);
    }
}
