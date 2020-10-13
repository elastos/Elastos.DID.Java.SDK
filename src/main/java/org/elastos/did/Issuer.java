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

import org.elastos.did.VerifiableCredential.Builder;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.MalformedDIDException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A issuer is the DID to issue Credential. Issuer includes issuer's did and
 * issuer's sign key.
 */
public class Issuer {
	private DIDDocument self;
	private DIDURL signKey;

	private static final Logger log = LoggerFactory.getLogger(Issuer.class);

	/**
	 * Constructs Issuer object with the given value.
	 *
	 * @param doc the Issuer's document
	 * @param signKey the specified issuer's key to sign
	 * @throws DIDStoreException there is no store to attatch
	 * @throws InvalidKeyException the sign key is not an authenication key.
	 */
	public Issuer(DIDDocument doc, DIDURL signKey)
			throws DIDStoreException, InvalidKeyException {
		if (doc == null)
			throw new IllegalArgumentException();

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
	public Issuer(DIDDocument doc, String signKey)
			throws DIDStoreException, InvalidKeyException {
		this(doc, signKey != null ? new DIDURL(doc.getSubject(), signKey) : null);
	}

	/**
	 * Constructs Issuer object with the given value.
	 *
	 * @param doc the Issuer's document
	 * @throws DIDStoreException there is no store to attach
	 * @throws InvalidKeyException the sign key is not an authentication key
	 */
	public Issuer(DIDDocument doc)
			throws DIDStoreException, InvalidKeyException {
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
	public Issuer(DID did, DIDURL signKey, DIDStore store)
			throws DIDStoreException, InvalidKeyException {
		if (did == null || store == null)
			throw new IllegalArgumentException();

		DIDDocument doc = store.loadDid(did);
		if (doc == null)
			throw new DIDStoreException("Can not load DID.");

		init(doc, signKey);
	}

	/**
	 * Constructs Issuer object with the given value.
	 *
	 * @param did the Issuer's DID
	 * @param signKey the specified issuer's key to sign
	 * @param store the DIDStore object
	 * @throws MalformedDIDException if the DID is invalid
	 * @throws DIDStoreException there is no store to attach
	 * @throws InvalidKeyException the sign key is not an authentication key
	 */
	public Issuer(String did, String signKey, DIDStore store)
			throws MalformedDIDException, DIDStoreException, InvalidKeyException {
		this(new DID(did),
				signKey != null ? new DIDURL(new DID(did), signKey) : null,
				store);
	}

	/**
	 * Constructs Issuer object with the given value.
	 *
	 * @param did the Issuer's DID
	 * @param store the DIDStore object
	 * @throws DIDStoreException there is no store to attach
	 * @throws InvalidKeyException the sign key is not an authentication key
	 */
	public Issuer(DID did, DIDStore store)
			throws DIDStoreException, InvalidKeyException {
		this(did, null, store);
	}

	/**
	 * Constructs Issuer object with the given value.
	 *
	 * @param did the Issuer's DID
	 * @param store the DIDStore object
	 * @throws MalformedDIDException if the DID is invalid
	 * @throws DIDStoreException there is no store to attach
	 * @throws InvalidKeyException the sign key is not an authentication key
	 */
	public Issuer(String did, DIDStore store)
			throws MalformedDIDException, DIDStoreException, InvalidKeyException {
		this(new DID(did), null, store);
	}

	private void init(DIDDocument doc, DIDURL signKey)
			throws DIDStoreException, InvalidKeyException {
		this.self = doc;

		if (signKey == null) {
			signKey = self.getDefaultPublicKeyId();
		} else {
			if (!self.isAuthenticationKey(signKey))
				throw new InvalidKeyException("Not an authentication key.");
		}

		if (!doc.hasPrivateKey(signKey))
			throw new InvalidKeyException("No private key.");

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

	public String sign(String storepass, byte[] data) throws DIDStoreException {
		try {
			return self.sign(signKey, storepass, data);
		} catch (InvalidKeyException ignore) {
			// should never happen
			log.error("INTERNAL - Signing digest", ignore);
			throw new DIDStoreException(ignore);
		}
	}

	/**
	 * Issue Credential to the specified DID.
	 *
	 * @param did the owner of Credential
	 * @return the VerifiableCredential builder to issuer Credential
	 */
	public Builder issueFor(DID did) {
		if (did == null)
			throw new IllegalArgumentException();

		return new Builder(this, did);
	}

	/**
	 * Issue Credential to the specified DID.
	 *
	 * @param did the owner of Credential
	 * @return the VerifiableCredential builder to issuer Credential
	 */
	public Builder issueFor(String did) {
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		return issueFor(_did);
	}
}
