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
 * An expanded (not compact/serialized) Signed JSON Web Token.
 *
 * @param <B> the type of the JWS body contents, either a String or a Claim instance.
 */
public class Jws<B> extends Jwt<B> {
	/**
	 * Constructs the a Jws instance from an internal implementation object.
	 *
	 * @param impl An io.jsonwebtoken.Jws object
	 */
	protected Jws(io.jsonwebtoken.Jws<?> impl) {
		super(impl);
	}

	/**
	 * Get the internal implementation object.
	 *
	 * @return the io.jsonwebtoken.Jws object
	 */
	protected io.jsonwebtoken.Jws<?> getImplAsJws() {
		return (io.jsonwebtoken.Jws<?>) getImpl();
	}

	/**
	 * Returns the JWS {@link JwsHeader} or {@code null} if not present.
	 *
	 * @return the JWS {@link JwsHeader} or {@code null} if not present.
	 */
	@Override
	public JwsHeader getHeader() {
		return getImplAsJws().getHeader() != null ?
				new JwsHeader(getImplAsJws().getHeader()) : null;
	}

	/**
	 * Get signature of the JWS.
	 * @return the signature string
	 */
	public String getSignature() {
		return getImplAsJws().getSignature();
	}
}
