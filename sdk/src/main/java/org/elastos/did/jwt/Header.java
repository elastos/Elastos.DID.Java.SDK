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
import java.util.Map;
import java.util.Set;

import io.jsonwebtoken.Jwts;

/**
 * A JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-5">header</a>.
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
 * header.{@link Map#put(Object, Object) put}("headerParamName", "headerParamValue");
 * </pre>
 *
 * <h2>Creation</h2>
 *
 * <p>It is easiest to create a {@code Header} instance by calling one of the
 * {@link Jwts#header() JWTs.header()} factory methods.</p>
 */
public class Header implements Map<String, Object> {
	/** JWT {@code Type} (typ) value: <code>"JWT"</code> */
	public static final String JWT_TYPE = "JWT";

	/** JWT {@code Type} header parameter name: <code>"typ"</code> */
	public static final String TYPE = "typ";

	/** JWT {@code Content Type} header parameter name: <code>"cty"</code> */
	public static final String CONTENT_TYPE = "cty";

	/**
	 * JWT {@code Compression Algorithm} header parameter name:
	 * <code>"zip"</code>
	 */
	public static final String COMPRESSION_ALGORITHM = "zip";

	private io.jsonwebtoken.Header<?> impl;

	/**
	 * Constructs the Header with the an internal implementation object.
	 *
	 * @param impl An io.jsonwebtoken.Header object
	 */
	protected Header(io.jsonwebtoken.Header<?> impl) {
		this.impl = impl;
	}

	/**
	 * Get the internal implementation object.
	 *
	 * @return the io.jsonwebtoken.Header object
	 */
	protected io.jsonwebtoken.Header<?> getImpl() {
		return impl;
	}

	/**
	 * Returns the <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-5.1">
	 * <code>typ</code></a> (type) header value or {@code null} if not present.
	 *
	 * @return the {@code typ} header value or {@code null} if not present.
	 */
	public String getType() {
		return getImpl().getType();
	}

	/**
	 * Sets the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-5.1">
	 * <code>typ</code></a> (Type) header value. A {@code null} value will
	 * remove the property from the map.
	 *
	 * @param typ the JWT {@code typ} header value or {@code null} to
	 *            remove the property from the map.
	 * @return the {@code Header} instance for method chaining.
	 */
	public Header setType(String typ) {
		getImpl().setType(typ);
		return this;
	}

	/**
	 * Returns the <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-5.2">
	 * <code>cty</code></a> (Content Type) header value or {@code null} if not
	 * present.
	 *
	 * <p>
	 * In the normal case where nested signing or encryption operations are not
	 * employed (i.e. a compact serialization JWT), the use of this header
	 * parameter is NOT RECOMMENDED. In the case that nested signing or
	 * encryption is employed, this Header Parameter MUST be present; in this
	 * case, the value MUST be {@code JWT}, to indicate that a Nested JWT is
	 * carried in this JWT. While media type names are not case-sensitive, it is
	 * RECOMMENDED that {@code JWT} always be spelled using uppercase characters
	 * for compatibility with legacy implementations. See <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#appendix-A.2">JWT
	 * Appendix A.2</a> for an example of a Nested JWT.
	 * </p>
	 *
	 * @return the {@code typ} header parameter value or {@code null} if not
	 *         present.
	 */
	public String getContentType() {
		return getImpl().getContentType();
	}

	/**
	 * Sets the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-5.2">
	 * <code>cty</code></a> (Content Type) header parameter value. A
	 * {@code null} value will remove the property from the map.
	 *
	 * <p>
	 * In the normal case where nested signing or encryption operations are not
	 * employed (i.e. a compact serialization JWT), the use of this header
	 * parameter is NOT RECOMMENDED. In the case that nested signing or
	 * encryption is employed, this Header Parameter MUST be present; in this
	 * case, the value MUST be {@code JWT}, to indicate that a Nested JWT is
	 * carried in this JWT. While media type names are not case-sensitive, it is
	 * RECOMMENDED that {@code JWT} always be spelled using uppercase characters
	 * for compatibility with legacy implementations. See <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#appendix-A.2">
	 * JWT Appendix A.2</a> for an example of a Nested JWT.
	 * </p>
	 *
	 * @param cty the JWT {@code cty} header value or {@code null} to
	 *            remove the property from the map.
	 * @return the {@code Header} instance for method chaining.
	 */
	public Header setContentType(String cty) {
		getImpl().setContentType(cty);
		return this;
	}

	/**
	 * Returns the JWT <code>zip</code> (Compression Algorithm) header value or
	 * {@code null} if not present.
	 *
	 * @return the {@code zip} header parameter value or {@code null} if not
	 *         present.
	 */
	public String getCompressionAlgorithm() {
		return getImpl().getCompressionAlgorithm();
	}

	/**
	 * Sets the JWT <code>zip</code> (Compression Algorithm) header parameter
	 * value. A {@code null} value will remove the property from the map.
	 *
	 * <p>
	 * The compression algorithm is NOT part of the <a href=
	 * "https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25">JWT
	 * specification</a> and must be used carefully since, is not expected that
	 * other libraries (including previous versions of this one) be able to
	 * deserialize a compressed JTW body correctly.
	 * </p>
	 *
	 * @param zip the JWT compression algorithm {@code zip} value or
	 *            {@code null} to remove the property from the map.
	 * @return the {@code Header} instance for method chaining.
	 */
	public Header setCompressionAlgorithm(String zip) {
		getImpl().setCompressionAlgorithm(zip);
		return this;
	}

	/**
	 * Returns the number of header values in this Header.
	 *
	 * @return the number of header values in this map
	 */
	@Override
	public int size() {
		return getImpl().size();
	}

	/**
	 * Returns true if this map contains no header values.
	 *
	 * @return true if this Claims contains no header values
	 */
	@Override
	public boolean isEmpty() {
		return getImpl().isEmpty();
	}

	/**
	 * Returns {@code true} if this Header contains a mapping for the specified
	 * key.  More formally, returns {@code true} if and only if
	 * this map contains a mapping for a key {@code k} such that
	 * {@code Objects.equals(key, k)}.  (There can be
	 * at most one such mapping.)
	 *
	 * @param key key whose presence in this headers is to be tested
	 * @return {@code true} if this Header contains a mapping for the specified
	 *         key
	 */
	@Override
	public boolean containsKey(Object key) {
		checkArgument(key != null, "Invalid key");
		return getImpl().containsKey(key);
	}

	/**
	 * Returns {@code true} if this Header maps one or more keys to the
	 * specified value. More formally, returns {@code true} if and only if
	 * this Header contains at least one mapping to a value {@code v} such that
	 * {@code Objects.equals(value, v)}.  This operation
	 * will probably require time linear in the map size for most
	 * implementations of the {@code Map} interface.
	 *
	 * @param value value whose presence in this Header is to be tested
	 * @return {@code true} if this Header maps one or more keys to the
	 *         specified value
	 */
	@Override
	public boolean containsValue(Object value) {
		return getImpl().containsValue(value);
	}

	/**
	 * Returns the value to which the specified key is mapped,
	 * or {@code null} if this Header contains no mapping for the key.
	 *
	 * <p>More formally, if this Header contains a mapping from a key
	 * {@code k} to a value {@code v} such that
	 * {@code Objects.equals(key, k)},
	 * then this method returns {@code v}; otherwise
	 * it returns {@code null}.  (There can be at most one such mapping.)
	 *
	 * @param key the key whose associated value is to be returned
	 * @return the value to which the specified key is mapped, or
	 *         {@code null} if this Header contains no mapping for the key
	 */
	@Override
	public Object get(Object key) {
		checkArgument(key != null, "Invalid key");
		return getImpl().get(key);
	}

	/**
	 * Associates the specified value with the specified key in this Header
	 * (optional operation).  If the map previously contained a mapping for
	 * the key, the old value is replaced by the specified value.  (A Header
	 * {@code h} is said to contain a mapping for a key {@code k} if and only
	 * if {@link #containsKey(Object) m.containsKey(k)} would return
	 * {@code true}.)
	 *
	 * @param key key with which the specified value is to be associated
	 * @param value value to be associated with the specified key
	 * @return the previous value associated with {@code key}, or
	 *         {@code null} if there was no mapping for {@code key}.
	 *         (A {@code null} return can also indicate that the map
	 *         previously associated {@code null} with {@code key},
	 *         if the implementation supports {@code null} values.)
	 */
	@Override
	public Object put(String key, Object value) {
		checkArgument(key != null && !key.isEmpty(), "Invalid key");
		return getImpl().put(key, value);
	}

	/**
	 * Removes the mapping for a key from this Header if it is present
	 * (optional operation).   More formally, if this Header contains a mapping
	 * from key {@code k} to value {@code v} such that
	 * {@code Objects.equals(key, k)}, that mapping
	 * is removed.  (The Header can contain at most one such mapping.)
	 *
	 * <p>Returns the value to which this map previously associated the key,
	 * or {@code null} if the Header contained no mapping for the key.
	 *
	 * <p>The map will not contain a mapping for the specified key once the
	 * call returns.
	 *
	 * @param key key whose mapping is to be removed from the Header
	 * @return the previous value associated with {@code key}, or
	 *         {@code null} if there was no mapping for {@code key}.
	 */
	@Override
	public Object remove(Object key) {
		checkArgument(key != null, "Invalid key");
		return getImpl().remove(key);
	}

	/**
	 * Copies all of the mappings from the specified map to this Header
	 * (optional operation).  The effect of this call is equivalent to that
	 * of calling {@link #put(Object,Object) put(k, v)} on this Header once
	 * for each mapping from key {@code k} to value {@code v} in the
	 * specified map.  The behavior of this operation is undefined if the
	 * specified map is modified while the operation is in progress.
	 *
	 * @param map mappings to be stored in this Header
	 */
	@Override
	public void putAll(Map<? extends String, ? extends Object> map) {
		checkArgument(map != null, "Invalid map");
		getImpl().putAll(map);
	}

	/**
	 * Removes all of the mappings from this Header (optional operation).
	 * The Header will be empty after this call returns.
	 */
	@Override
	public void clear() {
		getImpl().clear();
	}

	/**
	 * Returns a {@link Set} view of the keys contained in this Header.
	 * The set is backed by the Header, so changes to the Header are
	 * reflected in the set, and vice-versa.  If the Header is modified
	 * while an iteration over the set is in progress (except through
	 * the iterator's own {@code remove} operation), the results of
	 * the iteration are undefined.  The set supports element removal,
	 * which removes the corresponding mapping from the Header, via the
	 * {@code Iterator.remove}, {@code Set.remove},
	 * {@code removeAll}, {@code retainAll}, and {@code clear}
	 * operations.  It does not support the {@code add} or {@code addAll}
	 * operations.
	 *
	 * @return a set view of the keys contained in this Header
	 */
	@Override
	public Set<String> keySet() {
		return getImpl().keySet();
	}

	/**
	 * Returns a {@link Collection} view of the values contained in this Header.
	 * The collection is backed by the Header, so changes to the Header are
	 * reflected in the collection, and vice-versa.  If the Header is
	 * modified while an iteration over the collection is in progress
	 * (except through the iterator's own {@code remove} operation),
	 * the results of the iteration are undefined.  The collection
	 * supports element removal, which removes the corresponding
	 * mapping from the Header, via the {@code Iterator.remove},
	 * {@code Collection.remove}, {@code removeAll},
	 * {@code retainAll} and {@code clear} operations.  It does not
	 * support the {@code add} or {@code addAll} operations.
	 *
	 * @return a collection view of the values contained in this Header
	 */
	@Override
	public Collection<Object> values() {
		return getImpl().values();
	}

	/**
	 * Returns a {@link Set} view of the mappings contained in this Header.
	 * The set is backed by the Header, so changes to the Header are
	 * reflected in the set, and vice-versa.  If the Header is modified
	 * while an iteration over the set is in progress (except through
	 * the iterator's own {@code remove} operation, or through the
	 * {@code setValue} operation on a Header entry returned by the
	 * iterator) the results of the iteration are undefined.  The set
	 * supports element removal, which removes the corresponding
	 * mapping from the Header, via the {@code Iterator.remove},
	 * {@code Set.remove}, {@code removeAll}, {@code retainAll} and
	 * {@code clear} operations.  It does not support the
	 * {@code add} or {@code addAll} operations.
	 *
	 * @return a set view of the mappings contained in this Header
	 */
	@Override
	public Set<Entry<String, Object>> entrySet() {
		return getImpl().entrySet();
	}
}
