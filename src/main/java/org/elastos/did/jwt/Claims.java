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
 * A JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4">Claims set</a>.
 *
 * <p>
 * This is ultimately a map and any values can be added to it, but JWT
 * standard names are provided as type-safe getters and setters for convenience.
 * </p>
 *
 * <p>
 * Because this interface extends {@code Map&lt;String, Object&gt;},
 * if you would like to add your own properties, you simply use map methods,
 * for example:
 * </p>
 *
 * <pre>
 * claims.{@link Map#put(Object, Object) put}("someKey", "someValue");
 * </pre>
 *
 * <h3>Creation</h3>
 *
 * <p>
 * It is easiest to create a {@code Claims} instance by calling one of the
 * {@link JwtBuilder#createClaims() JwtBuilder.createClaims()} factory methods.
 * </p>
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

	/**
	 * Construct a Claims instance form an internal implementation object.
	 *
	 * @param impl An io.jsonwebtoken.Claims object
	 */
	protected Claims(io.jsonwebtoken.Claims impl) {
		this.impl = impl;
	}

	/**
	 * Get the internal implementation object.
	 *
	 * @return the io.jsonwebtoken.Claims object
	 */
	protected io.jsonwebtoken.Claims getImpl() {
		return impl;
	}

	/**
	 * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.1">
	 * <code>iss</code></a> (issuer) value or {@code null} if not present.
	 *
	 * @return the JWT {@code iss} value or {@code null} if not present
	 */
	public String getIssuer() {
		return impl.getIssuer();
	}

	/**
	 * Sets the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.1">
	 * <code>iss</code></a> (issuer) value. A {@code null} value will remove the
	 * property from the Claims.
	 *
	 * @param iss the JWT {@code iss} value or {@code null} to remove the
	 *            property from the Claims
	 * @return the {@code Claims} instance for method chaining
	 */
	public Claims setIssuer(String iss) {
		impl.setIssuer(iss);
		return this;
	}

	/**
	 * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.2">
	 * <code>sub</code></a> (subject) value or {@code null} if not present.
	 *
	 * @return the JWT {@code sub} value or {@code null} if not present
	 */
	public String getSubject() {
		return impl.getSubject();
	}

	/**
	 * Sets the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.2">
	 * <code>sub</code></a> (subject) value. A {@code null} value will remove
	 * the property from the Claims.
	 *
	 * @param sub the JWT {@code sub} value or {@code null} to remove the
	 *            property from the Claims
	 * @return the {@code Claims} instance for method chaining
	 */
	public Claims setSubject(String sub) {
		impl.setSubject(sub);
		return this;
	}

	/**
	 * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.3">
	 * <code>aud</code></a> (audience) value or {@code null} if not present.
	 *
	 * @return the JWT {@code aud} value or {@code null} if not present
	 */
	public String getAudience() {
		return impl.getAudience();
	}

	/**
	 * Sets the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.3">
	 * <code>aud</code></a> (audience) value. A {@code null} value will remove
	 * the property from the Claims.
	 *
	 * @param aud the JWT {@code aud} value or {@code null} to remove the
	 *            property from the Claims
	 * @return the {@code Claims} instance for method chaining
	 */
	public Claims setAudience(String aud) {
		impl.setAudience(aud);
		return this;
	}

	/**
	 * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.4">
	 * <code>exp</code></a> (expiration) timestamp or {@code null} if not
	 * present.
	 *
	 * <p>
	 * A JWT obtained after this timestamp should not be used.
	 * </p>
	 *
	 * @return the JWT {@code exp} value or {@code null} if not present
	 */
	public Date getExpiration() {
		return impl.getExpiration();
	}

	/**
	 * Sets the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.4">
	 * <code>exp</code></a> (expiration) timestamp. A {@code null} value will
	 * remove the property from the Claims.
	 *
	 * <p>
	 * A JWT obtained after this timestamp should not be used.
	 * </p>
	 *
	 * @param exp the JWT {@code exp} value or {@code null} to remove the
	 *            property from the Claims
	 * @return the {@code Claims} instance for method chaining
	 */
	public Claims setExpiration(Date exp) {
		impl.setExpiration(exp);
		return this;
	}

	/**
	 * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.5">
	 * <code>nbf</code></a> (not before) timestamp or {@code null} if not
	 * present.
	 *
	 * <p>
	 * A JWT obtained before this timestamp should not be used.
	 * </p>
	 *
	 * @return the JWT {@code nbf} value or {@code null} if not present
	 */
	public Date getNotBefore() {
		return impl.getNotBefore();
	}

	/**
	 * Sets the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.5">
	 * <code>nbf</code></a> (not before) timestamp. A {@code null} value will
	 * remove the property from the Claims.
	 *
	 * <p>
	 * A JWT obtained before this timestamp should not be used.
	 * </p>
	 *
	 * @param nbf the JWT {@code nbf} value or {@code null} to remove the
	 *            property from the Claims
	 * @return the {@code Claims} instance for method chaining
	 */
	public Claims setNotBefore(Date nbf) {
		impl.setNotBefore(nbf);
		return this;
	}

	/**
	 * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.6">
	 * <code>iat</code></a> (issued at) timestamp or {@code null} if not
	 * present.
	 *
	 * <p>
	 * If present, this value is the timestamp when the JWT was created.
	 * </p>
	 *
	 * @return the JWT {@code nbf} value or {@code null} if not present
	 */
	public Date getIssuedAt() {
		return impl.getIssuedAt();
	}

	/**
	 * Sets the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.6">
	 * <code>iat</code></a> (issued at) timestamp. A {@code null} value will
	 * remove the property from the Claims.
	 *
	 * <p>
	 * The value is the timestamp when the JWT was created.
	 * </p>
	 *
	 * @param iat the JWT {@code iat} value or {@code null} to remove the
	 *            property from the Claims
	 * @return the {@code Claims} instance for method chaining.
	 */
	public Claims setIssuedAt(Date iat) {
		impl.setIssuedAt(iat);
		return this;
	}

	/**
	 * Returns the JWTs <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.7">
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
	 * @return the JWT {@code jti} value or {@code null} if not present
	 */
	public String getId() {
		return impl.getId();
	}

	/**
	 * Sets the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.7">
	 * <code>jti</code></a> (JWT ID) value. A {@code null} value will remove the
	 * property from the Claims.
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
	 *            property from the Claims
	 * @return the {@code Claims} instance for method chaining
	 */
	public Claims setId(String jti) {
		impl.setId(jti);
		return this;
	}

	/**
	 * Returns the JWTs claim ({@code claimName}) value as a type
	 * {@code requiredType}, or {@code null} if not present.
	 *
	 * <p>
	 * SDK only converts simple String, Date, Long, Integer, Short and
	 * Byte types automatically.
	 * </p>
	 *
	 * @param claimName name of claim
	 * @param requiredType the type of the value expected to be returned
	 * @param <T> the type of the value expected to be returned
	 * @return the JWT {@code claimName} value or {@code null} if not present
	 */
	public <T> T get(String claimName, Class<T> requiredType) {
		checkArgument(claimName != null && !claimName.isEmpty(), "Invalid key");
		return impl.get(claimName, requiredType);
	}

	/**
	 * Returns the number of claimName-claimValue mappings in this Claims.
	 *
	 * @return the number of claimName-claimValue mappings in this Claims
	 */
	@Override
	public int size() {
		return impl.size();
	}

	/**
	 * Returns true if this Claims contains no claimName-claimValue mappings.
	 *
	 * @return true if this Claims contains no claimName-claimValue mappings
	 */
	@Override
	public boolean isEmpty() {
		return impl.isEmpty();
	}

	/**
	 * Returns {@code true} if this Claims contains a mapping for the specified
	 * key.  More formally, returns {@code true} if and only if
	 * this Claims contains a mapping for a key {@code k} such that
	 * {@code Objects.equals(key, k)}.  (There can be
	 * at most one such mapping.)
	 *
	 * @param key key whose presence in this Claims is to be tested
	 * @return {@code true} if this Claims contains a mapping for the specified
	 *         key
	 */
	@Override
	public boolean containsKey(Object key) {
		checkArgument(key != null, "Invalid key");
		return impl.containsKey(key);
	}

	/**
	 * Returns {@code true} if this Claims maps one or more keys to the
	 * specified value.  More formally, returns {@code true} if and only if
	 * this Claims contains at least one mapping to a value {@code v} such that
	 * {@code Objects.equals(value, v)}.  This operation
	 * will probably require time linear in the Claims size for most
	 * implementations of the {@code Map} interface.
	 *
	 * @param value value whose presence in this Claims is to be tested
	 * @return {@code true} if this Claims maps one or more keys to the
	 *         specified value
	 */
	@Override
	public boolean containsValue(Object value) {
		return impl.containsValue(value);
	}

	/**
	 * Returns the value to which the specified key is mapped,
	 * or {@code null} if this Claims contains no mapping for the key.
	 *
	 * <p>More formally, if this Claims contains a mapping from a key
	 * {@code k} to a value {@code v} such that
	 * {@code Objects.equals(key, k)},
	 * then this method returns {@code v}; otherwise
	 * it returns {@code null}.  (There can be at most one such mapping.)
	 *
	 * @param key the key whose associated value is to be returned
	 * @return the value to which the specified key is mapped, or
	 *         {@code null} if this Claims contains no mapping for the key
	 */
	@Override
	public Object get(Object key) {
		checkArgument(key != null, "Invalid key");
		return impl.get(key);
	}

	/**
	 * Returns the JSON string value to which the specified key is mapped,
	 * or {@code null} if this Claims contains no mapping for the key.
	 *
	 * <p>More formally, if this Claims contains a mapping from a key
	 * {@code k} to a value {@code v} such that
	 * {@code Objects.equals(key, k)},
	 * then this method returns {@code v}; otherwise
	 * it returns {@code null}.  (There can be at most one such mapping.)
	 *
	 * @param key the key whose associated value is to be returned
	 * @return the JSON string to which the specified key is mapped
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

	/**
	 * Associates the specified value with the specified key in this Claims
	 * (optional operation).  If the Claims previously contained a mapping for
	 * the key, the old value is replaced by the specified value.  (A Claims
	 * {@code m} is said to contain a mapping for a key {@code k} if and only
	 * if {@link #containsKey(Object) m.containsKey(k)} would return
	 * {@code true}.)
	 *
	 * @param key key with which the specified value is to be associated
	 * @param value value to be associated with the specified key
	 * @return the previous value associated with {@code key}, or
	 *         {@code null} if there was no mapping for {@code key}.
	 *         (A {@code null} return can also indicate that the Claims
	 *         previously associated {@code null} with {@code key},
	 *         if the implementation supports {@code null} values.)
	 */
	@Override
	public Object put(String key, Object value) {
		checkArgument(key != null && !key.isEmpty(), "Invalid key");

		return impl.put(key, value);
	}

	/**
	 * Associates the specified value with the specified key in this Claims
	 * (optional operation).
	 *
	 * @param key the key string
	 * @param json the json string
	 * @return the previous value associated with key, or null if there was
	 * 		   no mapping for key. (A null return can also indicate that
	 *         the Claims previously associated null with key, if the
	 *         implementation supports null values.)
	 */
	public Object putWithJson(String key, String json) {
		checkArgument(key != null && !key.isEmpty(), "Invalid key");
		checkArgument(json != null && !json.isEmpty(), "Invalid json");

		return impl.put(key, json2Map(json));
	}

	/**
	 * Removes the claimName from this Claims if it is present
	 * (optional operation).   More formally, if this Claims contains a mapping
	 * from key {@code k} to value {@code v} such that
	 * {@code Objects.equals(key, k)}, that mapping
	 * is removed.
	 *
	 * <p>Returns the value to which this Claims previously associated the key,
	 * or {@code null} if the Claims contained no mapping for the key.
	 *
	 * <p>The Claims will not contain a mapping for the specified key once the
	 * call returns.
	 *
	 * @param key the claimName to be removed from the Claims
	 * @return the previous value associated with {@code key}, or
	 *         {@code null} if there was no clainName for {@code key}.
	 */
	@Override
	public Object remove(Object key) {
		checkArgument(key != null, "Invalid key");
		return impl.remove(key);
	}

	/**
	 * Copies all of the mappings from the specified map to this Claims
	 * (optional operation).  The effect of this call is equivalent to that
	 * of calling {@link #put(Object,Object) put(k, v)} on this Claims once
	 * for each mapping from key {@code k} to value {@code v} in the
	 * specified map.  The behavior of this operation is undefined if the
	 * specified map is modified while the operation is in progress.
	 *
	 * @param map claims to be stored in this Claims
	 */
	@Override
	public void putAll(Map<? extends String, ? extends Object> map) {
		checkArgument(map != null, "Invalid map");
		impl.putAll(map);
	}

	/**
	 * Deserialize the JSON string to map, then copies all of the mappings
	 * from the map to this Claims.
	 *
	 * @param json the JSON claims
	 */
	public void putAllWithJson(String json) {
		checkArgument(json != null && !json.isEmpty(), "Invalid json");
		impl.putAll(json2Map(json));
	}

	/**
	 * Removes all of the claimed entries from this Claims (optional operation).
	 * The Claims will be empty after this call returns.
	 */
	@Override
	public void clear() {
		impl.clear();
	}

	/**
	 * Returns a {@link Set} view of the claimNames contained in this Claims.
	 * The set is backed by the Claims, so changes to the Claims are
	 * reflected in the set, and vice-versa.  If the Claims is modified
	 * while an iteration over the set is in progress (except through
	 * the iterator's own {@code remove} operation), the results of
	 * the iteration are undefined.  The set supports element removal,
	 * which removes the corresponding mapping from the Claims, via the
	 * {@code Iterator.remove}, {@code Set.remove},
	 * {@code removeAll}, {@code retainAll}, and {@code clear}
	 * operations.  It does not support the {@code add} or {@code addAll}
	 * operations.
	 *
	 * @return a set view of the keys contained in this Claims
	 */
	@Override
	public Set<String> keySet() {
		return impl.keySet();
	}

	/**
	 * Returns a {@link Collection} view of the claimed values contained
	 * in this Claims.
	 *
	 * The collection is backed by the Claims, so changes to the Claims are
	 * reflected in the collection, and vice-versa.  If the Claims is
	 * modified while an iteration over the collection is in progress
	 * (except through the iterator's own {@code remove} operation),
	 * the results of the iteration are undefined.  The collection
	 * supports element removal, which removes the corresponding
	 * mapping from the Claims, via the {@code Iterator.remove},
	 * {@code Collection.remove}, {@code removeAll},
	 * {@code retainAll} and {@code clear} operations.  It does not
	 * support the {@code add} or {@code addAll} operations.
	 *
	 * @return a collection view of the claimed values contained in this Claims
	 */
	@Override
	public Collection<Object> values() {
		return impl.values();
	}

	/**
	 * Returns a {@link Set} view of the claimed entries contained in this claims.
	 * The set is backed by the Claims, so changes to the Claims are
	 * reflected in the set, and vice-versa.  If the Claims is modified
	 * while an iteration over the set is in progress (except through
	 * the iterator's own {@code remove} operation, or through the
	 * {@code setValue} operation on a Claims entry returned by the
	 * iterator) the results of the iteration are undefined.  The set
	 * supports element removal, which removes the corresponding
	 * mapping from the Claims, via the {@code Iterator.remove},
	 * {@code Set.remove}, {@code removeAll}, {@code retainAll} and
	 * {@code clear} operations.  It does not support the
	 * {@code add} or {@code addAll} operations.
	 *
	 * @return a set view of the claimed entries contained in this Claims
	 */
	@Override
	public Set<Entry<String, Object>> entrySet() {
		return impl.entrySet();
	}

	/**
	 * Deserialize a JSON string into Map.
	 *
	 * @param json the JSON string
	 * @return the deserialized {@code Map&lt;String, Object&gt;}
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
