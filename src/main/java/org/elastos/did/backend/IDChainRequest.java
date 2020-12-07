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
import org.elastos.did.TransferTicket;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.crypto.Base64;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
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
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The class records the information of IDChain Request.
 */
@JsonPropertyOrder({ IDChainRequest.HEADER,
	IDChainRequest.PAYLOAD,
	IDChainRequest.PROOF })
public class IDChainRequest extends DIDObject<IDChainRequest> {
	/**
	 * The specification string of IDChain DID Request
	 */
	public static final String DID_SPECIFICATION = "elastos/did/1.0";

	/**
	 * The specification string of IDChain Credential Request
	 */
	public static final String CREDENTIAL_SPECIFICATION = "elastos/credential/1.0";

	protected static final String HEADER = "header";
	protected static final String PAYLOAD = "payload";
	protected static final String PROOF = "proof";
	private static final String SPECIFICATION = "specification";
	private static final String OPERATION = "operation";
	private static final String PREVIOUS_TXID = "previousTxid";
	private static final String TICKET = "ticket";
	private static final String TYPE = "type";
	private static final String VERIFICATION_METHOD = "verificationMethod";
	private static final String SIGNATURE = "signature";

	private static final Logger log = LoggerFactory.getLogger(IDChainRequest.class);

	@JsonProperty(HEADER)
	private Header header;
	@JsonProperty(PAYLOAD)
	private String payload;
	@JsonProperty(PROOF)
	private Proof proof;

	// fields for DID request
	private DID did;
	private DIDDocument doc;

	// fields for credential request
	private DIDURL id;
	private VerifiableCredential vc;

	/**
     * The IDChain Request Operation
	 */
	public static enum Operation {
		/**
		 * Create a new DID
		 */
		CREATE(DID_SPECIFICATION),
		/**
		 * Update an exist DID
		 */
		UPDATE(DID_SPECIFICATION),
		/**
		 * Transfer the DID' ownership
		 */
		TRANSFER(DID_SPECIFICATION),
		/**
		 * Deactivate a DID
		 */
		DEACTIVATE(DID_SPECIFICATION),
		/**
		 * Declare a credential
		 */
		DECLARE(CREDENTIAL_SPECIFICATION),
		/**
		 * Revoke a credential
		 */
		REVOKE(CREDENTIAL_SPECIFICATION);

		private String specification;

		private Operation(String specification) {
			this.specification = specification;
		}

		public String getSpecification() {
			return specification;
		}

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

	@JsonPropertyOrder({ SPECIFICATION, OPERATION, PREVIOUS_TXID, TICKET })
	@JsonInclude(Include.NON_NULL)
	protected static class Header {
		@JsonProperty(SPECIFICATION)
		private String specification;
		@JsonProperty(OPERATION)
		private Operation operation;
		@JsonProperty(PREVIOUS_TXID)
		@JsonInclude(Include.NON_NULL)
		private String previousTxid;
		@JsonProperty(TICKET)
		@JsonInclude(Include.NON_NULL)
		private String ticket;
		private TransferTicket transferTicket;

		@JsonCreator
		private Header(@JsonProperty(value = SPECIFICATION, required = true) String spec) {
			this.specification = spec;
		}

		private Header(Operation operation, String previousTxid) {
			this(operation.getSpecification());
			this.operation = operation;
			this.previousTxid = previousTxid;
		}

		private Header(Operation operation, TransferTicket ticket) {
			this(operation.getSpecification());
			this.operation = operation;

			String json = ticket.toString(true);
			this.ticket = Base64.encodeToString(json.getBytes(),
					Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
			this.transferTicket = ticket;
		}

		private Header(Operation operation) {
			this(operation.getSpecification());
			this.operation = operation;
		}

		public String getSpecification() {
			return specification;
		}

		public Operation getOperation() {
			return operation;
		}

		public String getPreviousTxid() {
			return previousTxid;
		}

		public String getTicket() {
			return ticket;
		}

		@JsonSetter(TICKET)
		private void setTicket(String ticket) throws MalformedIDChainRequestException {
			if (ticket == null || ticket.isEmpty())
				throw new MalformedIDChainRequestException("Missing ticket");

			String json = new String(Base64.decode(ticket,
					Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP));

			try {
				this.transferTicket = TransferTicket.parse(json);
			} catch (DIDSyntaxException e) {
				throw new MalformedIDChainRequestException("Invalid ticket", e);
			}

			this.ticket = ticket;
		}

		public TransferTicket getTransferTicket()  {
			return transferTicket;
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
		private Proof(@JsonProperty(value = TYPE) String type,
				@JsonProperty(value = VERIFICATION_METHOD, required = true) DIDURL verificationMethod,
				@JsonProperty(value = SIGNATURE, required = true) String signature) {
			this.type = type != null ? type : Constants.DEFAULT_PUBLICKEY_TYPE;
			this.verificationMethod = verificationMethod;
			this.signature = signature;
		}

		private Proof(DIDURL verificationMethod, String signature) {
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

	@JsonCreator
	protected IDChainRequest() {}

	private IDChainRequest(Operation operation) {
		this.header = new Header(operation);
	}

	private IDChainRequest(Operation operation, String previousTxid) {
		this.header = new Header(operation, previousTxid);
	}

	private IDChainRequest(Operation operation, TransferTicket ticket) {
		this.header = new Header(operation, ticket);
	}

	/**
	 * Constructs the 'create' DID Request.
	 *
	 * @param doc the DID Document be packed into Request
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public static IDChainRequest createDid(DIDDocument doc, DIDURL signKey,
			String storepass) throws DIDStoreException, InvalidKeyException {
		IDChainRequest request = new IDChainRequest(Operation.CREATE);
		request.setPayload(doc);
		try {
			request.seal(signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			// should never happen
			log.error("INTERNAL - Seal the request", ignore);
			return null;
		}

		return request;
	}

	/**
	 * Constructs the 'update' DID Request.
	 *
	 * @param doc the DID Document be packed into Request
	 * @param previousTxid the previous transaction id string
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public static IDChainRequest updateDid(DIDDocument doc, String previousTxid,
			DIDURL signKey, String storepass)
			throws DIDStoreException, InvalidKeyException {
		IDChainRequest request = new IDChainRequest(Operation.UPDATE, previousTxid);
		request.setPayload(doc);
		try {
			request.seal(signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			// should never happen
			log.error("INTERNAL - Seal the request", ignore);
			return null;
		}

		return request;
	}

	/**
	 * Constructs the 'transfer' DID Request.
	 *
	 * @param doc target DID document
	 * @param ticket the transfer ticket object
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public static IDChainRequest transferDid(DIDDocument doc, TransferTicket ticket,
			DIDURL signKey, String storepass) throws DIDStoreException, InvalidKeyException {
		IDChainRequest request = new IDChainRequest(Operation.TRANSFER, ticket);
		request.setPayload(doc);
		try {
			request.seal(signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			// should never happen
			log.error("INTERNAL - Seal the request", ignore);
			return null;
		}

		return request;
	}


	/**
	 * Constructs the 'deactivate' DID Request.
	 *
	 * @param doc the DID Document be packed into Request
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public static IDChainRequest deactivateDid(DIDDocument doc, DIDURL signKey,
			String storepass) throws DIDStoreException, InvalidKeyException {
		IDChainRequest request = new IDChainRequest(Operation.DEACTIVATE);
		request.setPayload(doc);
		try {
			request.seal(signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			// should never happen
			log.error("INTERNAL - Seal the request", ignore);
			return null;
		}

		return request;
	}

	/**
	 * Constructs the 'deactivate' DID Request.
	 *
	 * @param target the DID to be deactivated
	 * @param targetSignKey the target DID's key to sign
	 * @param doc the authorizer's document
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDResolveException the target DID can not resolved
	 * @throws DIDStoreException there is no store to attach
	 * @throws InvalidKeyException there is no an authentication key
	 */
	public static IDChainRequest deactivateDid(DID target, DIDURL targetSignKey,
			DIDDocument doc, DIDURL signKey, String storepass)
			throws DIDResolveException, DIDStoreException, InvalidKeyException {
		IDChainRequest request = new IDChainRequest(Operation.DEACTIVATE);
		request.setPayload(target);
		try {
			request.seal(targetSignKey, doc, signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			// should never happen
			log.error("INTERNAL - Seal the request", ignore);
			return null;
		}

		return request;
	}

	/**
	 * Constructs the 'declare' credential Request.
	 *
	 * @param vc the VerifiableCredential object needs to be declare
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public static IDChainRequest declareCredential(VerifiableCredential vc,
			DIDURL signKey, String storepass) throws DIDStoreException, InvalidKeyException {
		// TODO:
		IDChainRequest request = new IDChainRequest(Operation.DECLARE);
		request.setPayload(vc);
		try {
			request.seal(signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			// should never happen
			log.error("INTERNAL - Seal the request", ignore);
			return null;
		}

		return request;
	}

	/**
	 * Constructs the 'revoke' credential Request.
	 *
	 * @param id the VerifiableCredential object needs to be revoke
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public static IDChainRequest RevokeCredential(VerifiableCredential vc,
			DIDURL signKey, String storepass) throws DIDStoreException, InvalidKeyException {
		// TODO:
		IDChainRequest request = new IDChainRequest(Operation.REVOKE);
		request.setPayload(vc);
		try {
			request.seal(signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			// should never happen
			log.error("INTERNAL - Seal the request", ignore);
			return null;
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
	 * Get transfer ticket object.
	 *
	 * @return the TransferTicket object
	 */
	public TransferTicket getTransferTicket() {
		return header.getTransferTicket();
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

	public DIDURL getCredentialId() {
		return id;
	}

	public VerifiableCredential getCredential() {
		return vc;
	}

	private void setPayload(DID did) throws DIDResolveException {
		this.did = did;
		this.doc = did.resolve(true);
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

	private void setPayload(VerifiableCredential vc) {
		this.id = vc.getId();
		this.vc = vc;

		if (header.getOperation() == Operation.DECLARE) {
			String json = vc.toString(true);

			this.payload = Base64.encodeToString(json.getBytes(),
					Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
		} else {
			this.payload = vc.getId().toString();
		}
	}

	/**
	 * Get the proof object of the IDChainRequest.
	 *
	 * @return the proof object
	 */
	public Proof getProof() {
		return proof;
	}

	@Override
	protected void sanitize(boolean withProof) throws MalformedIDChainRequestException {
		if (header == null)
			throw new MalformedIDChainRequestException("Missing header");

		if (header.getSpecification() == null ||
				!header.getSpecification().equals(DID_SPECIFICATION))
			throw new MalformedIDChainRequestException("Unsupported specification");

		if (header.getOperation() == Operation.UPDATE &&
				(header.getPreviousTxid() == null || header.getPreviousTxid().isEmpty()))
			throw new MalformedIDChainRequestException("Missing previousTxid");

		if (header.getOperation() == Operation.TRANSFER &&
				(header.getTicket() == null || header.getTicket().isEmpty()))
			throw new MalformedIDChainRequestException("Missing ticket");

		if (payload == null || payload.isEmpty())
			throw new MalformedIDChainRequestException("Missing payload");

		if (withProof) {
			if (proof == null)
				throw new MalformedIDChainRequestException("Missing proof");

			try {
				if (header.getOperation() != Operation.DEACTIVATE) {
					String json = new String(Base64.decode(payload,
							Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP));

					doc = DIDDocument.parse(json);
					did = doc.getSubject();
				} else {
					did = new DID(payload);
					try {
						doc = did.resolve(true);
					} catch (DIDResolveException ignore) {
						doc = null;
					}
				}
			} catch (DIDException e) {
				throw new MalformedIDChainRequestException("Invalid payload", e);
			}

			if (proof.verificationMethod.getDid() == null)
				proof.verificationMethod = new DIDURL(did, proof.verificationMethod.toString());
		}
	}

	// Helper method for IDChainTransaction
	void sanitizeHelper() throws MalformedIDChainRequestException {
		sanitize(true);
	}

	private byte[][] getSigningInputs() {
		String prevtxid = getOperation() == Operation.UPDATE ? getPreviousTxid() : "";
		String ticket = getOperation() == Operation.TRANSFER ? header.getTicket() : "";

		byte[][] inputs = new byte[][] {
			header.getSpecification().getBytes(),
			header.getOperation().toString().getBytes(),
			prevtxid.getBytes(),
			ticket.getBytes(),
			payload.getBytes()
		};

		return inputs;
	}

	public void seal(DIDURL signKey, String storepass)
			throws MalformedIDChainRequestException, DIDStoreException, InvalidKeyException {
		if (!doc.isAuthenticationKey(signKey))
			throw new InvalidKeyException("Not an authentication key.");

		sanitize(false);

		String signature = doc.sign(signKey, storepass, getSigningInputs());
		proof = new Proof(signKey, signature);
	}

	private void seal(DIDURL targetSignKey, DIDDocument doc,
			DIDURL signKey, String storepass)
			throws MalformedIDChainRequestException, DIDStoreException, InvalidKeyException {
		if (!this.doc.isAuthorizationKey(targetSignKey))
			throw new InvalidKeyException("Not an authorization key: " + targetSignKey);

		if (!doc.isAuthenticationKey(signKey))
			throw new InvalidKeyException("Not an authentication key: " + signKey);


		sanitize(false);

		String signature = doc.sign(signKey, storepass, getSigningInputs());
		proof = new Proof(targetSignKey, signature);
	}

	protected boolean isTicketValid() {
		return true;
	}

	/**
	 * Judge whether the IDChain Request is valid or not.
	 *
	 * @return the returned value is true if IDChain Request is valid;
	 *         the returned value is false if IDChain Request is not valid.
	 * @throws DIDTransactionException there is no invalid key.
	 */
	public boolean isValid() throws DIDTransactionException {
		DIDURL signKey = proof.getVerificationMethod();

		try {
			if (doc == null)
				doc = did.resolve(true);
		} catch (DIDResolveException e) {
			throw new DIDTransactionException("Resolve DID: " + did, e);
		}

		if (doc == null)
			throw new DIDTransactionException("Can not resolve DID: " + did);

		if (!doc.isValid())
			return false;

		if (getOperation() != Operation.DEACTIVATE) {
			if (!doc.isAuthenticationKey(signKey))
				return false;
		} else {
			if (!doc.isAuthenticationKey(signKey) && !doc.isAuthorizationKey(signKey))
				return false;
		}

		return doc.verify(proof.getVerificationMethod(), proof.getSignature(), getSigningInputs());
	}
}
