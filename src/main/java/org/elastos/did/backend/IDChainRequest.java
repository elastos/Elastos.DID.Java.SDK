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

package org.elastos.did.backend;

import org.elastos.did.Constants;
import org.elastos.did.DID;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDObject;
import org.elastos.did.DIDURL;
import org.elastos.did.crypto.Base64;
import org.elastos.did.exception.DIDBackendException;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDTransactionException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.MalformedIDChainRequestException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The class records the information of IDChain Request.
 */
@JsonPropertyOrder({ IDChainRequest.HEADER,
	IDChainRequest.PAYLOAD,
	IDChainRequest.PROOF })
public class IDChainRequest extends DIDObject<IDChainRequest> {
	/**
	 * The specification string of IDChain Request
	 */
	public static final String CURRENT_SPECIFICATION = "elastos/did/1.0";

	protected static final String HEADER = "header";
	protected static final String PAYLOAD = "payload";
	protected static final String PROOF = "proof";
	private static final String SPECIFICATION = "specification";
	private static final String OPERATION = "operation";
	private static final String PREVIOUS_TXID = "previousTxid";
	private static final String TYPE = "type";
	private static final String VERIFICATION_METHOD = "verificationMethod";
	private static final String SIGNATURE = "signature";

	private static final Logger log = LoggerFactory.getLogger(IDChainRequest.class);

	/**
     * The IDChain Request Operation
	 */
	public static enum Operation {
		/**
		 * the new did operation
		 */
		CREATE,
		/**
		 * the update did operation
		 */
		UPDATE,
		/**
		 * the deactivate did operation
		 */
		DEACTIVATE;

		@Override
		@JsonValue
		public String toString() {
			return name().toLowerCase();
		}

		@JsonCreator
		public static Operation fromString(String name) {
			return valueOf(name.toUpperCase());
		}
	}

	@JsonPropertyOrder({ SPECIFICATION, OPERATION, PREVIOUS_TXID })
	@JsonInclude(Include.NON_NULL)
	public static class Header {
		@JsonProperty(SPECIFICATION)
		private String specification;
		@JsonProperty(OPERATION)
		private Operation operation;
		@JsonProperty(PREVIOUS_TXID)
		private String previousTxid;

		@JsonCreator
		protected Header(@JsonProperty(value = SPECIFICATION, required = true) String spec) {
			this.specification = spec;
		}

		protected Header(Operation operation, String previousTxid) {
			this(CURRENT_SPECIFICATION);
			this.operation = operation;
			this.previousTxid = previousTxid;
		}

		protected Header(Operation operation) {
			this(operation, null);
		}

		public String getSpecification() {
			return specification;
		}

		public Operation getOperation() {
			return operation;
		}

		protected void setOperation(Operation operation) {
			this.operation = operation;
		}

		public String getPreviousTxid() {
			return previousTxid;
		}

		protected void setPreviousTxid(String previousTxid) {
			this.previousTxid = previousTxid;
		}
	}

	@JsonPropertyOrder({ TYPE, VERIFICATION_METHOD, SIGNATURE })
	public static class Proof {
		@JsonProperty(TYPE)
		private String type;
		@JsonProperty(VERIFICATION_METHOD)
		private DIDURL verificationMethod;
		@JsonProperty(SIGNATURE)
		private String signature;

		@JsonCreator
		protected Proof(@JsonProperty(value = TYPE) String type,
				@JsonProperty(value = VERIFICATION_METHOD, required = true) DIDURL verificationMethod,
				@JsonProperty(value = SIGNATURE, required = true) String signature) {
			this.type = type != null ? type : Constants.DEFAULT_PUBLICKEY_TYPE;
			this.verificationMethod = verificationMethod;
			this.signature = signature;
		}

		protected Proof(DIDURL verificationMethod, String signature) {
			this(null, verificationMethod, signature);
		}

		public String getType() {
			return type;
		}

		public DIDURL getVerificationMethod() {
			return verificationMethod;
		}

		public String getSignature() {
			return signature;
		}
	}

	@JsonProperty(HEADER)
	private Header header;
	@JsonProperty(PAYLOAD)
	private String payload;
	@JsonProperty(PROOF)
	private Proof proof;

	private DID did;
	private DIDDocument doc;

	@JsonCreator
	protected IDChainRequest() {}

	private IDChainRequest(Operation operation) {
		this.header = new Header(operation);
	}

	private IDChainRequest(Operation operation, String previousTxid) {
		this.header = new Header(operation, previousTxid);
	}

	/**
	 * Constructs the 'create' IDChain Request.
	 *
	 * @param doc the DID Document be packed into Request
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public static IDChainRequest create(DIDDocument doc, DIDURL signKey,
			String storepass) throws DIDStoreException, InvalidKeyException {
		IDChainRequest request = new IDChainRequest(Operation.CREATE);
		request.setPayload(doc);
		try {
			request.seal(signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			// should never happen
			log.error("INTERNAL - Seal the request", ignore);
		}

		return request;
	}

	/**
	 * Constructs the 'update' IDChain Request.
	 *
	 * @param doc the DID Document be packed into Request
	 * @param previousTxid the previous transaction id string
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public static IDChainRequest update(DIDDocument doc, String previousTxid,
			DIDURL signKey, String storepass)
			throws DIDStoreException, InvalidKeyException {
		IDChainRequest request = new IDChainRequest(Operation.UPDATE, previousTxid);
		request.setPayload(doc);
		try {
			request.seal(signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			// should never happen
			log.error("INTERNAL - Seal the request", ignore);
		}

		return request;
	}

	/**
	 * Constructs the 'deactivate' IDChain Request.
	 *
	 * @param doc the DID Document be packed into Request
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public static IDChainRequest deactivate(DIDDocument doc, DIDURL signKey,
			String storepass) throws DIDStoreException, InvalidKeyException {
		IDChainRequest request = new IDChainRequest(Operation.DEACTIVATE);
		request.setPayload(doc);
		try {
			request.seal(signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			// should never happen
			log.error("INTERNAL - Seal the request", ignore);
		}

		return request;
	}

	/**
	 * Constructs the 'deactivate' IDChain Request.
	 *
	 * @param target the DID to be deactivated
	 * @param targetSignKey the target DID's key to sign
	 * @param doc the authorizer's document
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public static IDChainRequest deactivate(DID target, DIDURL targetSignKey,
			DIDDocument doc, DIDURL signKey, String storepass)
			throws DIDStoreException, InvalidKeyException {
		IDChainRequest request = new IDChainRequest(Operation.DEACTIVATE);
		request.setPayload(target);
		try {
			request.seal(targetSignKey, doc, signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			// should never happen
			log.error("INTERNAL - Seal the request", ignore);
		}

		return request;
	}

	/**
	 * Get operation string.
	 * @return the operation string
	 */
	public Operation getOperation() {
		return header.getOperation();
	}

	/**
	 * Get previous transaction id string.
	 *
	 * @return the transaction id string
	 */
	public String getPreviousTxid() {
		return header.getPreviousTxid();
	}

	/**
	 * Get payload of IDChain Request.
	 *
	 * @return the payload string
	 */
	public String getPayload() {
		return payload;
	}

	/**
	 * Get DID of IDChain Request.
	 *
	 * @return the DID object
	 */
	public DID getDid() {
		return did;
	}

	/**
	 * Get DID Document of IDChain Request.
	 *
	 * @return the DIDDocument object
	 */
	public DIDDocument getDocument() {
		return doc;
	}

	private void setPayload(DID did) {
		this.did = did;
		this.doc = null;
		this.payload = did.toString();
	}

	private void setPayload(DIDDocument doc) {
		this.did = doc.getSubject();
		this.doc = doc;

		if (header.getOperation() != Operation.DEACTIVATE) {
			String json = doc.toString(true);

			this.payload = Base64.encodeToString(json.getBytes(),
					Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
		} else {
			this.payload = doc.getSubject().toString();
		}
	}

	public Proof getProof() {
		return proof;
	}

	@Override
	protected void sanitize(boolean withProof) throws MalformedIDChainRequestException {
		if (header == null)
			throw new MalformedIDChainRequestException("Missing header");

		if (header.getSpecification() == null ||
				!header.getSpecification().equals(CURRENT_SPECIFICATION))
			throw new MalformedIDChainRequestException("Unsupported specification");

		if (header.getOperation() == Operation.UPDATE &&
				(header.getPreviousTxid() == null || header.getPreviousTxid().isEmpty()))
			throw new MalformedIDChainRequestException("Missing previousTxid");

		if (payload == null || payload.isEmpty())
			throw new MalformedIDChainRequestException("Missing payload");

		if (withProof) {
			try {
				if (header.getOperation() != Operation.DEACTIVATE) {
					String json = new String(Base64.decode(payload,
							Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP));

					doc = DIDDocument.parse(json);
					did = doc.getSubject();
				} else {
					did = new DID(payload);
					doc = null;
				}
			} catch (DIDException e) {
				throw new MalformedIDChainRequestException("Invalid payload", e);
			}

			if (proof == null)
				throw new MalformedIDChainRequestException("Missing proof");

			if (proof.verificationMethod.getDid() == null)
				proof.verificationMethod = new DIDURL(did, proof.verificationMethod.toString());
		}
	}

	// Helper method for IDChainTransaction
	void sanitizeHelper() throws MalformedIDChainRequestException {
		sanitize(true);
	}

	private void seal(DIDURL signKey, String storepass)
			throws MalformedIDChainRequestException, DIDStoreException, InvalidKeyException {
		if (!doc.isAuthenticationKey(signKey))
			throw new InvalidKeyException("Not an authentication key.");

		sanitize(false);

		String prevtxid = getOperation() == Operation.UPDATE ? getPreviousTxid() : "";

		byte[][] inputs = new byte[][] {
			header.getSpecification().getBytes(),
			header.getOperation().toString().getBytes(),
			prevtxid.getBytes(),
			payload.getBytes()
		};

		String signature = doc.sign(signKey, storepass, inputs);
		this.proof = new Proof(signKey, signature);
	}

	private void seal(DIDURL targetSignKey, DIDDocument doc,
			DIDURL signKey, String storepass)
			throws MalformedIDChainRequestException, DIDStoreException, InvalidKeyException {
		if (!doc.isAuthenticationKey(signKey))
			throw new InvalidKeyException("Not an authentication key.");

		sanitize(false);

		String prevtxid = getOperation() == Operation.UPDATE ? getPreviousTxid() : "";

		byte[][] inputs = new byte[][] {
			header.getSpecification().getBytes(),
			header.getOperation().toString().getBytes(),
			prevtxid.getBytes(),
			payload.getBytes()
		};

		String signature = doc.sign(signKey, storepass, inputs);
		this.proof = new Proof(targetSignKey, signature);
	}

	/**
	 * Judge whether the IDChain Request is valid or not.
	 *
	 * @return the returned value is true if IDChain Request is valid;
	 *         the returned value is false if IDChain Request is not valid.
	 * @throws DIDTransactionException there is no invalid key.
	 */
	public boolean isValid() throws DIDTransactionException {
		DIDDocument doc = null;
		DIDURL signKey = proof.getVerificationMethod();

		if (getOperation() != Operation.DEACTIVATE) {
			doc = this.doc;
			if (!doc.isAuthenticationKey(signKey))
				return false;
		} else {
			try {
				doc = did.resolve();
				if (!doc.isAuthenticationKey(signKey) &&
						!doc.isAuthorizationKey(signKey))
					return false;
			} catch (DIDBackendException e) {
				new DIDTransactionException(e);
			}
		}

		String prevtxid = getOperation() == Operation.UPDATE ? getPreviousTxid() : "";

		byte[][] inputs = new byte[][] {
			header.getSpecification().getBytes(),
			header.getOperation().toString().getBytes(),
			prevtxid.getBytes(),
			payload.getBytes()
		};

		return doc.verify(signKey, proof.getSignature(), inputs);
	}
}
