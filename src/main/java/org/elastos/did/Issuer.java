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

package org.elastos.did;

import static com.google.common.base.Preconditions.checkArgument;

import org.elastos.did.VerifiableCredential.Builder;
import org.elastos.did.exception.DIDNotFoundException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.InvalidKeyException;

/**
 * A issuer is the DID to issue Credential. Issuer includes issuer's did and
 * issuer's sign key.
 */
public class Issuer {
	private DIDDocument self;
	private DIDURL signKey;

	/**
	 * Constructs Issuer object with the given value.
	 *
	 * @param doc the Issuer's document
	 * @param signKey the specified issuer's key to sign
	 * @throws DIDStoreException there is no store to attatch
	 * @throws InvalidKeyException the sign key is not an authenication key.
	 */
	public Issuer(DIDDocument doc, DIDURL signKey) throws DIDStoreException {
		checkArgument(doc != null, "Invalid document");

		init(doc, signKey);
	}

	/**
	 * Constructs Issuer object with the given value.
	 *
	 * @param doc the Issuer's document
	 * @param signKey the specified issuer's key to sign
	 * @throws DIDStoreException there is no store to attatch
	 * @throws InvalidKeyException the sign key is not an authenication key.
	 */
	public Issuer(DIDDocument doc, String signKey) throws DIDStoreException {
		this(doc, DIDURL.valueOf(doc.getSubject(), signKey));
	}

	/**
	 * Constructs Issuer object with the given value.
	 *
	 * @param doc the Issuer's document
	 * @throws DIDStoreException there is no store to attach
	 * @throws InvalidKeyException the sign key is not an authentication key
	 */
	public Issuer(DIDDocument doc) throws DIDStoreException {
		this(doc, (DIDURL)null);
	}

	/**
	 * Constructs Issuer object with the given value.
	 *
	 * @param did the Issuer's DID
	 * @param signKey the specified issuer's key to sign
	 * @param store the DIDStore object
	 * @throws DIDStoreException there is no store to attach
	 * @throws InvalidKeyException the sign key is not an authentication key
	 */
	public Issuer(DID did, DIDURL signKey, DIDStore store) throws DIDStoreException {
		checkArgument(did != null, "Invalid did");
		checkArgument(store != null, "Invalid store");

		DIDDocument doc = store.loadDid(did);
		if (doc == null)
			throw new DIDNotFoundException(did.toString());

		init(doc, signKey);
	}

	/**
	 * Constructs Issuer object with the given value.
	 *
	 * @param did the Issuer's DID
	 * @param signKey the specified issuer's key to sign
	 * @param store the DIDStore object
	 * @throws DIDStoreException there is no store to attach
	 * @throws InvalidKeyException the sign key is not an authentication key
	 */
	public Issuer(String did, String signKey, DIDStore store)
			throws DIDStoreException {
		this(DID.valueOf(did), DIDURL.valueOf(did, signKey), store);
	}

	/**
	 * Constructs Issuer object with the given value.
	 *
	 * @param did the Issuer's DID
	 * @param store the DIDStore object
	 * @throws DIDStoreException there is no store to attach
	 * @throws InvalidKeyException the sign key is not an authentication key
	 */
	public Issuer(DID did, DIDStore store) throws DIDStoreException {
		this(did, null, store);
	}

	/**
	 * Constructs Issuer object with the given value.
	 *
	 * @param did the Issuer's DID
	 * @param store the DIDStore object
	 * @throws DIDStoreException there is no store to attach
	 * @throws InvalidKeyException the sign key is not an authentication key
	 */
	public Issuer(String did, DIDStore store) throws DIDStoreException {
		this(DID.valueOf(did), null, store);
	}

	private void init(DIDDocument doc, DIDURL signKey) throws DIDStoreException {
		this.self = doc;

		if (signKey == null) {
			signKey = self.getDefaultPublicKeyId();
			if (signKey == null)
				throw new InvalidKeyException("Need explict sign key or effective controller");
		} else {
			if (!self.isAuthenticationKey(signKey))
				throw new InvalidKeyException(signKey.toString());
		}

		if (!doc.hasPrivateKey(signKey))
			throw new InvalidKeyException("No private key: " + signKey);

		this.signKey = signKey;
	}

	/**
	 * Get Issuer's DID.
	 *
	 * @return the DID object
	 */
	public DID getDid() {
		return self.getSubject();
	}

	/**
	 * Get issuer's DIDDocument.
	 *
	 * @return the DIDDocument object.
	 */
	protected DIDDocument getDocument() {
		return self;
	}

	/**
	 * Get Issuer's sign key.
	 *
	 * @return the sign key
	 */
	public DIDURL getSignKey() {
		return signKey;
	}

	protected String sign(String storepass, byte[] data) throws DIDStoreException {
		return self.sign(signKey, storepass, data);
	}

	/**
	 * Issue Credential to the specified DID.
	 *
	 * @param did the owner of Credential
	 * @return the VerifiableCredential builder to issuer Credential
	 */
	public Builder issueFor(DID did) {
		checkArgument(did != null, "Invalid did");

		return new Builder(this, did);
	}

	/**
	 * Issue Credential to the specified DID.
	 *
	 * @param did the owner of Credential
	 * @return the VerifiableCredential builder to issuer Credential
	 */
	public Builder issueFor(String did) {
		return issueFor(DID.valueOf(did));
	}
}
