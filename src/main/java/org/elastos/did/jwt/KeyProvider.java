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

public interface KeyProvider {
	/**
	 * Get public key from KeyProvider
	 *
	 * @param id the owner of key
	 * @return the PublicKey object
	 * @throws InvalidKeyException the PublicKey is invalid.
	 */
	public PublicKey getPublicKey(String id) throws InvalidKeyException;

	/**
	 * Get private key from KeyProvider
	 *
	 * @param id the owner of key
	 * @param storepass the password for DIDStore
	 * @return the Privatekey object
	 * @throws InvalidKeyException the PrivateKey is invalid.
	 * @throws DIDStoreException there is no store to load private key.
	 */
	public PrivateKey getPrivateKey(String id, String storepass)
			throws InvalidKeyException, DIDStoreException;
}
