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
 * This class represents a VerifiableCredential issuer.
 *
 * <p>
 * This class can be instantiated by a DID, and use to issue credentials for
 * 3rd parties.
 * </p>
 */
public class Issuer {
	private DIDDocument self;
	private DIDURL signKey;

	/**
	 * Create an issuer instance by the specific DID and sign key id.
	 *
	 * @param doc the Issuer's DID document
	 * @param signKey the specified key to sign the credentials
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public Issuer(DIDDocument doc, DIDURL signKey) throws DIDStoreException {
		checkArgument(doc != null, "Invalid document");

		init(doc, signKey);
	}

	/**
	 * Create an issuer instance by the specific DID and sign key id.
	 *
	 * @param doc the Issuer's DID document
	 * @param signKey the specified key to sign the credentials
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public Issuer(DIDDocument doc, String signKey) throws DIDStoreException {
		this(doc, DIDURL.valueOf(doc.getSubject(), signKey));
	}

	/**
	 * Create an issuer instance by the specific DID and default key.
	 *
	 * @param doc the Issuer's DID document
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public Issuer(DIDDocument doc) throws DIDStoreException {
		this(doc, (DIDURL)null);
	}

	/**
	 * Create an issuer instance by the specific DID and sign key id.
	 *
	 * @param did the Issuer's DID object
	 * @param signKey the specified key to sign the credentials
	 * @param store where to load the issuer's document and keys
	 * @throws DIDStoreException if an error occurred when accessing the store
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
	 * Create an issuer instance by the specific DID and sign key id.
	 *
	 * @param did the Issuer's DID
	 * @param signKey the specified key to sign the credentials
	 * @param store where to load the issuer's document and keys
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public Issuer(String did, String signKey, DIDStore store)
			throws DIDStoreException {
		this(DID.valueOf(did), DIDURL.valueOf(did, signKey), store);
	}

	/**
	 * Create an issuer instance by the specific DID and the default key.
	 *
	 * @param did the Issuer's DID object
	 * @param store from where to load the issuer's document and keys
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public Issuer(DID did, DIDStore store) throws DIDStoreException {
		this(did, null, store);
	}

	/**
	 * Create an issuer instance by the specific DID and the default key.
	 *
	 * @param did the Issuer's DID
	 * @param store from where to load the issuer's document and keys
	 * @throws DIDStoreException if an error occurred when accessing the store
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
	 * Get the issuer's DID.
	 *
	 * @return the DID object
	 */
	public DID getDid() {
		return self.getSubject();
	}

	/**
	 * Get the issuer's DID document object.
	 *
	 * @return the DIDDocument object
	 */
	protected DIDDocument getDocument() {
		return self;
	}

	/**
	 * Get the key id that use to sign the credentials.
	 *
	 * @return the id of the sign key
	 */
	public DIDURL getSignKey() {
		return signKey;
	}

	String sign(String storepass, byte[] data) throws DIDStoreException {
		return self.sign(signKey, storepass, data);
	}

	/**
	 * Issue a credential to the given DID.
	 *
	 * @param did the owner of credential
	 * @return a VerifiableCredential.Builder object to issue the credential
	 */
	public Builder issueFor(DID did) {
		checkArgument(did != null, "Invalid did");

		return new Builder(this, did);
	}

	/**
	 * Issue a credential to the given DID.
	 *
	 * @param did the owner of credential
	 * @return a VerifiableCredential.Builder object to issue the credential
	 */
	public Builder issueFor(String did) {
		return issueFor(DID.valueOf(did));
	}
}
