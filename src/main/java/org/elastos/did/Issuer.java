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

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.MalformedCredentialException;
import org.elastos.did.exception.MalformedDIDException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class Issuer {
	private static final String DEFAULT_PUBLICKEY_TYPE = Constants.DEFAULT_PUBLICKEY_TYPE;
	private static final int MAX_VALID_YEARS = Constants.MAX_VALID_YEARS;

	private DIDDocument self;
	private DIDURL signKey;

	/**
	 * Contructs Issuer object with the given value.
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
	 * Contructs Issuer object with the given value.
	 *
	 * @param doc the Issuer's document
	 * @throws DIDStoreException there is no store to attatch.
	 * @throws InvalidKeyException the sign key is not an authenication key.
	 */
	public Issuer(DIDDocument doc)
			throws DIDStoreException, InvalidKeyException {
		this(doc, null);
	}

	/**
	 * Contructs Issuer object with the given value.
	 *
	 * @param did the Issuer's DID
	 * @param signKey the specified issuer's key to sign
	 * @param store the DIDStore object
	 * @throws DIDStoreException there is no store to attatch.
	 * @throws InvalidKeyException the sign key is not an authenication key.
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
	 * Contructs Issuer object with the given value.
	 *
	 * @param did the Issuer's DID
	 * @param store the DIDStore object
	 * @throws DIDStoreException there is no store to attatch.
	 * @throws InvalidKeyException the sign key is not an authenication key.
	 */
	public Issuer(DID did, DIDStore store)
			throws DIDStoreException, InvalidKeyException {
		this(did, null, store);
	}

	private void init(DIDDocument doc, DIDURL signKey)
			throws DIDStoreException, InvalidKeyException {
		this.self = doc;

		if (signKey == null) {
			signKey = self.getDefaultPublicKey();
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
	 * Get Issuer's sign key.
	 *
	 * @return the sign key
	 */
	public DIDURL getSignKey() {
		return signKey;
	}

	/**
	 * Issue Credential to the specified DID.
	 *
	 * @param did the owner of Credential
	 * @return the builder to edit Credential
	 */
	public CredentialBuilder issueFor(DID did) {
		if (did == null)
			throw new IllegalArgumentException();

		return new CredentialBuilder(did);
	}

	/**
	 * Issue Credential to the specified DID.
	 *
	 * @param did the owner of Credential
	 * @return the builder to edit Credential
	 */
	public CredentialBuilder issueFor(String did) {
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		return issueFor(_did);
	}

	public class CredentialBuilder {
		private DID target;
		private VerifiableCredential credential;

		/**
		 * Contructs the Builder for Credential to edit.
		 *
		 * @param target the owner of Credential
		 */
		protected CredentialBuilder(DID target) {
			this.target = target;

			credential = new VerifiableCredential();
			credential.setIssuer(self.getSubject());
		}

		/**
		 * Set Credential id.
		 *
		 * @param id the Credential id
		 * @return the CredentialBuilder object
		 */
		public CredentialBuilder id(DIDURL id) {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			if (id == null)
				throw new IllegalArgumentException();

			credential.setId(id);
			return this;
		}

		/**
		 * Set Credential id.
		 *
		 * @param id the Credential id
		 * @return the CredentialBuilder object
		 */
		public CredentialBuilder id(String id) {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			DIDURL _id = id == null ? null : new DIDURL(target, id);
			return id(_id);
		}

		/**
		 * Set Credential types.
		 *
		 * @param types the set of types
		 * @return the CredentialBuilder object
		 */
		public CredentialBuilder type(String ... types) {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			if (types == null || types.length == 0)
				throw new IllegalArgumentException();

			credential.setType(types);
			return this;
		}

		private Calendar getMaxExpires() {
			Calendar cal = Calendar.getInstance(Constants.UTC);
			if (credential.getIssuanceDate() != null)
				cal.setTime(credential.getIssuanceDate());
			cal.add(Calendar.YEAR, MAX_VALID_YEARS);

			return cal;
		}

        /**
         * Set expires time for Credential with max expires time.
         *
         * @return the CredentialBuilder object
         */
		public CredentialBuilder defaultExpirationDate() {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			credential.setExpirationDate(getMaxExpires().getTime());

			return this;
		}

		/**
		 * Set expires time for Credential.
		 *
		 * @param expirationDate the expires time
		 * @return the CredentialBuilder object
		 */
		public CredentialBuilder expirationDate(Date expirationDate) {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			if (expirationDate == null)
				return this;

			Calendar cal = Calendar.getInstance(Constants.UTC);
			cal.setTime(expirationDate);

			Calendar maxExpires = getMaxExpires();
			if (cal.after(maxExpires))
				cal = maxExpires;

			credential.setExpirationDate(cal.getTime());

			return this;
		}

		/**
		 * Set Credential's subject.
		 *
		 * @param properties the subject content
		 * @return the CredentialBuilder object
		 */
		public CredentialBuilder properties(Map<String, String> properties) {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			if (properties == null || properties.size() == 0)
				throw new IllegalArgumentException();

			ObjectMapper mapper = new ObjectMapper();
			ObjectNode node = mapper.createObjectNode();

			for (Map.Entry<String, String> entry : properties.entrySet())
				node.put(entry.getKey(), entry.getValue());

			return properties(node);
		}

		/**
		 * Set Credential's subject.
		 *
		 * @param properties the subject subject with json format
		 * @return the CredentialBuilder object
		 */
		public CredentialBuilder properties(String json) {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			if (json == null || json.isEmpty())
				throw new IllegalArgumentException();

			ObjectMapper mapper = new ObjectMapper();
			JsonNode node;
			try {
				node = mapper.readTree(json);
			} catch (IOException e) {
				throw new IllegalArgumentException(e);
			}

			return properties(node);
		}

		/**
		 * Set Credential's subject.
		 *
		 * @param properties the subject subject with JsonNode format
		 * @return the CredentialBuilder object
		 */
		public CredentialBuilder properties(JsonNode node) {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			if (node == null || node.size() == 0)
				throw new IllegalArgumentException();

			VerifiableCredential.CredentialSubject subject =
					new VerifiableCredential.CredentialSubject(target);
			subject.setProperties(node);
			credential.setSubject(subject);

			return this;
		}

		/**
		 * Finish the Credential editting.
		 *
		 * @param storepass the password for DIDStore
		 * @return the Credential object
		 * @throws MalformedCredentialException the Credential malformed.
		 * @throws DIDStoreException there is no store to attach
		 */
		public VerifiableCredential seal(String storepass)
				throws MalformedCredentialException, DIDStoreException {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			if (storepass == null || storepass.isEmpty())
				throw new IllegalArgumentException();

			credential.completeCheck();

			Calendar cal = Calendar.getInstance(Constants.UTC);
			credential.setIssuanceDate(cal.getTime());

			if (!credential.hasExpirationDate())
				defaultExpirationDate();

			String json = credential.toJson(true, true);
			String sig = self.sign(signKey, storepass, json.getBytes());

			VerifiableCredential.Proof proof = new VerifiableCredential.Proof(
					DEFAULT_PUBLICKEY_TYPE, signKey, sig);
			credential.setProof(proof);

			// Invalidate builder
			VerifiableCredential vc = credential;
			this.credential = null;

			return vc;
		}
	}
}
