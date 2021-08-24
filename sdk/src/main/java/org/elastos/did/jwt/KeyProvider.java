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

import java.security.PrivateKey;
import java.security.PublicKey;

import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.InvalidKeyException;

/**
 * A {@code KeyProvider} can be used by a JwtParser or JwtBulder to find a
 * signing key that should be used to verify or sign a JWS.
 *
 * Normally the {@code KeyProvider} related with a DID, the implementation
 * will load the key from DID document or DID store.
 */
public interface KeyProvider {
	/**
	 * Returns the signing key that should be used to validate a digital
	 * signature for the JWS.
	 *
	 * @param id the id(DIDURL format) of the key
	 * @return the JCE PublicKey object
	 * @throws InvalidKeyException the id is invalid, or the key is invalid
	 */
	public PublicKey getPublicKey(String id) throws InvalidKeyException;

	/**
	 * Returns the signing key that should be used to sign the digital
	 * signature for the JWS.
	 *
	 * @param id the id(DIDURL format) of the key
	 * @param storepass the password for DIDStore
	 * @return the JCE PrivateKey object
	 * @throws InvalidKeyException the id is invalid, or the key is invalid
	 * @throws DIDStoreException if error occurred when read the private key
	 * 			from DID store.
	 */
	public PrivateKey getPrivateKey(String id, String storepass)
			throws InvalidKeyException, DIDStoreException;
}
