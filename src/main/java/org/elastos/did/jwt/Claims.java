/*
 * Copyright (c) 2019 Elastos Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package org.elastos.did.jwt;

import static com.google.common.base.Preconditions.checkArgument;

import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import org.elastos.did.exception.UnknownInternalException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * The class records the body content of JWT(like map format).
 */
public class Claims implements Map<String, Object> {
	/** JWT {@code Issuer} claims parameter name: <code>"iss"</code> */
	public static final String ISSUER = "iss";

	/** JWT {@code Subject} claims parameter name: <code>"sub"</code> */
	public static final String SUBJECT = "sub";

	/** JWT {@code Audience} claims parameter name: <code>"aud"</code> */
	public static final String AUDIENCE = "aud";

	/** JWT {@code Expiration} claims parameter name: <code>"exp"</code> */
	public static final String EXPIRATION = "exp";

	/** JWT {@code Not Before} claims parameter name: <code>"nbf"</code> */
	public static final String NOT_BEFORE = "nbf";

	/** JWT {@code Issued At} claims parameter name: <code>"iat"</code> */
	public static final String ISSUED_AT = "iat";

	/** JWT {@code JWT ID} claims parameter name: <code>"jti"</code> */
	public static final String ID = "jti";

	private io.jsonwebtoken.Claims impl;

	protected Claims(io.jsonwebtoken.Claims impl) {
		this.impl = impl;
	}

	protected io.jsonwebtoken.Claims getImpl() {
		return impl;
	}

	/**
	 * Returns the JWT <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.1">
	 * <code>iss</code></a> (issuer) value or {@code null} if not present.
	 *
	 * @return the JWT {@code iss} value or {@code null} if not present.
	 */
	public String getIssuer() {
		return impl.getIssuer();
	}

	/**
	 * Sets the JWT <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.1">
	 * <code>iss</code></a> (issuer) value. A {@code null} value will remove the
	 * property from the JSON map.
	 *
	 * @param iss the JWT {@code iss} value or {@code null} to remove the
	 *            property from the JSON map.
	 * @return the {@code Claims} instance for method chaining.
	 */
	public Claims setIssuer(String iss) {
		impl.setIssuer(iss);
		return this;
	}

	/**
	 * Returns the JWT <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.2">
	 * <code>sub</code></a> (subject) value or {@code null} if not present.
	 *
	 * @return the JWT {@code sub} value or {@code null} if not present.
	 */
	public String getSubject() {
		return impl.getSubject();
	}

	/**
	 * Sets the JWT <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.2">
	 * <code>sub</code></a> (subject) value. A {@code null} value will remove
	 * the property from the JSON map.
	 *
	 * @param sub the JWT {@code sub} value or {@code null} to remove the
	 *            property from the JSON map.
	 * @return the {@code Claims} instance for method chaining.
	 */
	public Claims setSubject(String sub) {
		impl.setSubject(sub);
		return this;
	}

	/**
	 * Returns the JWT <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.3">
	 * <code>aud</code></a> (audience) value or {@code null} if not present.
	 *
	 * @return the JWT {@code aud} value or {@code null} if not present.
	 */
	public String getAudience() {
		return impl.getAudience();
	}

	/**
	 * Sets the JWT <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.3">
	 * <code>aud</code></a> (audience) value. A {@code null} value will remove
	 * the property from the JSON map.
	 *
	 * @param aud the JWT {@code aud} value or {@code null} to remove the
	 *            property from the JSON map.
	 * @return the {@code Claims} instance for method chaining.
	 */
	public Claims setAudience(String aud) {
		impl.setAudience(aud);
		return this;
	}

	/**
	 * Returns the JWT <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.4">
	 * <code>exp</code></a> (expiration) timestamp or {@code null} if not
	 * present.
	 *
	 * <p>
	 * A JWT obtained after this timestamp should not be used.
	 * </p>
	 *
	 * @return the JWT {@code exp} value or {@code null} if not present.
	 */
	public Date getExpiration() {
		return impl.getExpiration();
	}

	/**
	 * Sets the JWT <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.4">
	 * <code>exp</code></a> (expiration) timestamp. A {@code null} value will
	 * remove the property from the JSON map.
	 *
	 * <p>
	 * A JWT obtained after this timestamp should not be used.
	 * </p>
	 *
	 * @param exp the JWT {@code exp} value or {@code null} to remove the
	 *            property from the JSON map.
	 * @return the {@code Claims} instance for method chaining.
	 */
	public Claims setExpiration(Date exp) {
		impl.setExpiration(exp);
		return this;
	}

	/**
	 * Returns the JWT <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.5">
	 * <code>nbf</code></a> (not before) timestamp or {@code null} if not
	 * present.
	 *
	 * <p>
	 * A JWT obtained before this timestamp should not be used.
	 * </p>
	 *
	 * @return the JWT {@code nbf} value or {@code null} if not present.
	 */
	public Date getNotBefore() {
		return impl.getNotBefore();
	}

	/**
	 * Sets the JWT <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.5">
	 * <code>nbf</code></a> (not before) timestamp. A {@code null} value will
	 * remove the property from the JSON map.
	 *
	 * <p>
	 * A JWT obtained before this timestamp should not be used.
	 * </p>
	 *
	 * @param nbf the JWT {@code nbf} value or {@code null} to remove the
	 *            property from the JSON map.
	 * @return the {@code Claims} instance for method chaining.
	 */
	public Claims setNotBefore(Date nbf) {
		impl.setNotBefore(nbf);
		return this;
	}

	/**
	 * Returns the JWT <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.6">
	 * <code>iat</code></a> (issued at) timestamp or {@code null} if not
	 * present.
	 *
	 * <p>
	 * If present, this value is the timestamp when the JWT was created.
	 * </p>
	 *
	 * @return the JWT {@code nbf} value or {@code null} if not present.
	 */
	public Date getIssuedAt() {
		return impl.getIssuedAt();
	}

	/**
	 * Sets the JWT <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.6">
	 * <code>iat</code></a> (issued at) timestamp. A {@code null} value will
	 * remove the property from the JSON map.
	 *
	 * <p>
	 * The value is the timestamp when the JWT was created.
	 * </p>
	 *
	 * @param iat the JWT {@code iat} value or {@code null} to remove the
	 *            property from the JSON map.
	 * @return the {@code Claims} instance for method chaining.
	 */
	public Claims setIssuedAt(Date iat) {
		impl.setIssuedAt(iat);
		return this;
	}

	/**
	 * Returns the JWTs <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.7">
	 * <code>jti</code></a> (JWT ID) value or {@code null} if not present.
	 *
	 * <p>
	 * This value is a CaSe-SenSiTiVe unique identifier for the JWT. If
	 * available, this value is expected to be assigned in a manner that ensures
	 * that there is a negligible probability that the same value will be
	 * accidentally assigned to a different data object. The ID can be used to
	 * prevent the JWT from being replayed.
	 * </p>
	 *
	 * @return the JWT {@code jti} value or {@code null} if not present.
	 */
	public String getId() {
		return impl.getId();
	}

	/**
	 * Sets the JWT <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.7">
	 * <code>jti</code></a> (JWT ID) value. A {@code null} value will remove the
	 * property from the JSON map.
	 *
	 * <p>
	 * This value is a CaSe-SenSiTiVe unique identifier for the JWT. If
	 * specified, this value MUST be assigned in a manner that ensures that
	 * there is a negligible probability that the same value will be
	 * accidentally assigned to a different data object. The ID can be used to
	 * prevent the JWT from being replayed.
	 * </p>
	 *
	 * @param jti the JWT {@code jti} value or {@code null} to remove the
	 *            property from the JSON map.
	 * @return the {@code Claims} instance for method chaining.
	 */
	public Claims setId(String jti) {
		impl.setId(jti);
		return this;
	}

	/**
	 * Returns the JWTs claim ({@code claimName}) value as a type
	 * {@code requiredType}, or {@code null} if not present.
	 *
	 * @param key    name of claim
	 * @param requiredType the type of the value expected to be returned
	 * @param <T>          the type of the value expected to be returned
	 * @return the JWT {@code claimName} value or {@code null} if not present.
	 */
	public <T> T get(String key, Class<T> requiredType) {
		checkArgument(key != null && !key.isEmpty(), "Invalid key");
		return impl.get(key, requiredType);
	}

	@Override
	public int size() {
		return impl.size();
	}

	@Override
	public boolean isEmpty() {
		return impl.isEmpty();
	}

	@Override
	public boolean containsKey(Object key) {
		checkArgument(key != null, "Invalid key");
		return impl.containsKey(key);
	}

	@Override
	public boolean containsValue(Object value) {
		return impl.containsValue(value);
	}

	@Override
	public Object get(Object key) {
		checkArgument(key != null, "Invalid key");
		return impl.get(key);
	}

	/**
	 * Returns the value string to which the specified key is mapped,
	 * or null if this map contains no mapping for the key.
	 *
	 * @param key the key whose associated value is to be returned
	 * @return the value string to which the specified key is mapped
	 */
	public String getAsJson(Object key) {
		checkArgument(key != null, "Invalid key");

		Object v = impl.get(key);
		if (v == null)
			return null;

		ObjectMapper mapper = new ObjectMapper();
		try {
			return mapper.writeValueAsString(v);
		} catch (JsonProcessingException e) {
			throw new UnknownInternalException(e);
		}
	}

	@Override
	public Object put(String key, Object value) {
		checkArgument(key != null && !key.isEmpty(), "Invalid key");

		return impl.put(key, value);
	}

	/**
	 * Associates the specified value with the specified key in this map (optional operation).
	 *
	 * @param key the key string
	 * @param json the json string
	 * @return the previous value associated with key, or null if there was no mapping for key.
	 *         (A null return can also indicate that the map previously associated null with key,
	 *         if the implementation supports null values.)
	 */
	public Object putWithJson(String key, String json) {
		checkArgument(key != null && !key.isEmpty(), "Invalid key");
		checkArgument(json != null && !json.isEmpty(), "Invalid json");

		return impl.put(key, json2Map(json));
	}

	@Override
	public Object remove(Object key) {
		checkArgument(key != null, "Invalid key");
		return impl.remove(key);
	}

	@Override
	public void putAll(Map<? extends String, ? extends Object> map) {
		checkArgument(map != null, "Invalid map");
		impl.putAll(map);
	}

	/**
	 * Copies all of the mappings from the specified map to this map (optional operation).
	 *
	 * @param json the json string
	 */
	public void putAllWithJson(String json) {
		checkArgument(json != null && !json.isEmpty(), "Invalid json");
		impl.putAll(json2Map(json));
	}

	@Override
	public void clear() {
		impl.clear();
	}

	@Override
	public Set<String> keySet() {
		return impl.keySet();
	}

	@Override
	public Collection<Object> values() {
		return impl.values();
	}

	@Override
	public Set<Entry<String, Object>> entrySet() {
		return impl.entrySet();
	}

	/**
	 * Change json string into Map format.
	 *
	 * @param json the data's json string
	 * @return the Map data
	 */
	protected static Map<String, Object> json2Map(String json) {
		ObjectMapper mapper = new ObjectMapper();
		try {
			JsonNode node = mapper.readTree(json);
			Map<String, Object> map = mapper.convertValue(node,
					new TypeReference<Map<String, Object>>(){});

			return map;
		} catch (JsonProcessingException e) {
			throw new IllegalArgumentException(e);
		}
	}
}
