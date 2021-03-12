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

/**
 * The class defines JwsHeader object.
 *
 */
public class JwsHeader extends Header {
	/** JWS {@code Algorithm} header parameter name: <code>"alg"</code> */
	public static final String ALGORITHM = "alg";

	/** JWS {@code JWT Set URL} header parameter name: <code>"jku"</code> */
	public static final String JWK_SET_URL = "jku";

	/** JWS {@code JSON Web Key} header parameter name: <code>"jwk"</code> */
	public static final String JSON_WEB_KEY = "jwk";

	/** JWS {@code Key ID} header parameter name: <code>"kid"</code> */
	public static final String KEY_ID = "kid";

	/** JWS {@code X.509 URL} header parameter name: <code>"x5u"</code> */
	public static final String X509_URL = "x5u";

	/**
	 * JWS {@code X.509 Certificate Chain} header parameter name:
	 * <code>"x5c"</code>
	 */
	public static final String X509_CERT_CHAIN = "x5c";

	/**
	 * JWS {@code X.509 Certificate SHA-1 Thumbprint} header parameter name:
	 * <code>"x5t"</code>
	 */
	public static final String X509_CERT_SHA1_THUMBPRINT = "x5t";

	/**
	 * JWS {@code X.509 Certificate SHA-256 Thumbprint} header parameter name:
	 * <code>"x5t#S256"</code>
	 */
	public static final String X509_CERT_SHA256_THUMBPRINT = "x5t#S256";

	/** JWS {@code Critical} header parameter name: <code>"crit"</code> */
	public static final String CRITICAL = "crit";

	/**
	 * Constructs a JwsHeader instance from an internal implementation object.
	 *
	 * @param impl An io.jsonwebtoken.JwsHeader object
	 */
	protected JwsHeader(io.jsonwebtoken.JwsHeader<?> impl) {
		super(impl);
	}

	/**
	 * Get the internal implementation object.
	 *
	 * @return the io.jsonwebtoken.JwsHeader object
	 */
	protected io.jsonwebtoken.JwsHeader<?> getImplAsJwsHeader() {
		return (io.jsonwebtoken.JwsHeader<?>) getImpl();
	}

	/**
	 * Sets the JWS <code>typ</code> (Type) header value.
	 * A {@code null} value will remove the property from the map.
	 *
	 * @param typ the JWS {@code typ} header value or {@code null} to
	 *            remove the property from the map.
	 * @return the {@code JwsHeader} instance for method chaining.
	 */
	@Override
	public JwsHeader setType(String typ) {
		super.setType(typ);
		return this;
	}

	/**
	 * Sets the JWS <code>cty</code> (Content Type) header parameter value.
	 * A {@code null} value will remove the property from the map.
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
	 * @param cty the JWS {@code cty} header value or {@code null} to
	 *            remove the property from the map.
	 * @return the {@code Header} instance for method chaining.
	 */
	@Override
	public JwsHeader setContentType(String cty) {
		super.setContentType(cty);
		return this;
	}

	/**
	 * Sets the JWS <code>zip</code> (Compression Algorithm) header parameter
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
	 * @param zip the JWS compression algorithm {@code zip} value or
	 *            {@code null} to remove the property from the map.
	 * @return the {@code Header} instance for method chaining.
	 */
	@Override
	public JwsHeader setCompressionAlgorithm(String zip) {
		super.setCompressionAlgorithm(zip);
		return this;
	}

	/**
	 * Returns the JWS <a href="https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-4.1.1">
	 * <code>alg</code></a> (algorithm) header value or {@code null} if not
	 * present.
	 *
	 * <p>
	 * The algorithm header parameter identifies the cryptographic algorithm
	 * used to secure the JWS. Consider using
	 * {@link io.jsonwebtoken.SignatureAlgorithm#forName(String)
	 * SignatureAlgorithm.forName} to convert this string value to a type-safe
	 * enum instance.
	 * </p>
	 *
	 * @return the JWS {@code alg} header value or {@code null} if not present.
	 *         This will always be {@code non-null} on validly constructed JWS
	 *         instances, but could be {@code null} during construction.
	 */
	public String getAlgorithm() {
		return getImplAsJwsHeader().getAlgorithm();
	}

	/**
	 * Sets the JWT <a href="https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-4.1.1">
	 * <code>alg</code></a> (Algorithm) header value. A {@code null} value will
	 * remove the property from the header.
	 *
	 * <p>
	 * The algorithm header parameter identifies the cryptographic algorithm
	 * used to secure the JWS. Consider using a type-safe
	 * {@link io.jsonwebtoken.SignatureAlgorithm SignatureAlgorithm} instance
	 * and using its {@link io.jsonwebtoken.SignatureAlgorithm#getValue() value}
	 * as the argument to this method.
	 * </p>
	 *
	 * @param alg the JWS {@code alg} header value or {@code null} to remove the
	 *            property from the JSON map.
	 * @return the {@code Header} instance for method chaining.
	 */
	public JwsHeader setAlgorithm(String alg) {
		getImplAsJwsHeader().setAlgorithm(alg);
		return this;
	}

	/**
	 * Returns the JWS <a href="https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-4.1.4">
	 * <code>kid</code></a> (Key ID) header value or {@code null} if not
	 * present.
	 *
	 * <p>
	 * The keyId header parameter is a hint indicating which key was used to
	 * secure the JWS. This parameter allows originators to explicitly signal a
	 * change of key to recipients. The structure of the keyId value is
	 * unspecified.
	 * </p>
	 *
	 * <p>
	 * When used with a JWK, the keyId value is used to match a JWK
	 * {@code keyId} parameter value.
	 * </p>
	 *
	 * @return the JWS {@code kid} header value or {@code null} if not present.
	 */
	public String getKeyId() {
		return getImplAsJwsHeader().getKeyId();
	}

	/**
	 * Sets the JWT <a href="https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-4.1.4">
	 * <code>kid</code></a> (Key ID) header value. A {@code null} value will
	 * remove the property from the JSON map.
	 *
	 * <p>
	 * The keyId header parameter is a hint indicating which key was used to
	 * secure the JWS. This parameter allows originators to explicitly signal a
	 * change of key to recipients. The structure of the keyId value is
	 * unspecified.
	 * </p>
	 *
	 * <p>
	 * When used with a JWK, the keyId value is used to match a JWK
	 * {@code keyId} parameter value.
	 * </p>
	 *
	 * @param kid the JWS {@code kid} header value or {@code null} to remove the
	 *            property from the JSON map.
	 * @return the {@code Header} instance for method chaining.
	 */
	public JwsHeader setKeyId(String kid) {
		getImplAsJwsHeader().setKeyId(kid);
		return this;
	}
}
