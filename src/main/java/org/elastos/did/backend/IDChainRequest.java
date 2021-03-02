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
import org.elastos.did.DIDEntity;
import org.elastos.did.DIDURL;
import org.elastos.did.TransferTicket;
import org.elastos.did.crypto.Base64;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.MalformedIDChainRequestException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * The class records the information of IDChain Request.
 */
@JsonPropertyOrder({ IDChainRequest.HEADER,
	IDChainRequest.PAYLOAD,
	IDChainRequest.PROOF })
public abstract class IDChainRequest<T> extends DIDEntity<T> {
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

	protected static final String SPECIFICATION = "specification";
	private static final String OPERATION = "operation";
	private static final String PREVIOUS_TXID = "previousTxid";
	private static final String TICKET = "ticket";

	private static final String TYPE = "type";
	private static final String VERIFICATION_METHOD = "verificationMethod";
	private static final String SIGNATURE = "signature";

	@JsonProperty(HEADER)
	private Header header;
	@JsonProperty(PAYLOAD)
	private String payload;
	@JsonProperty(PROOF)
	private Proof proof;

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

		protected Proof(DIDURL verificationMethod, String signature) {
			this(null, verificationMethod, signature);
		}

		public String getType() {
			return type;
		}

		public DIDURL getVerificationMethod() {
			return verificationMethod;
		}

		protected void qualifyVerificationMethod(DID ref) {
			// TODO: need improve the impl
			if (verificationMethod.getDid() == null)
				verificationMethod = new DIDURL(ref, verificationMethod);
		}

		public String getSignature() {
			return signature;
		}
	}

	protected IDChainRequest() {}

	protected IDChainRequest(Operation operation) {
		this.header = new Header(operation);
	}

	protected IDChainRequest(Operation operation, String previousTxid) {
		this.header = new Header(operation, previousTxid);
	}

	protected IDChainRequest(Operation operation, TransferTicket ticket) {
		this.header = new Header(operation, ticket);
	}

	protected IDChainRequest(IDChainRequest<?> request) {
		this.header = request.header;
		this.payload = request.payload;
		this.proof = request.proof;
	}

	protected Header getHeader() {
		return header;
	}

	/**
	 * Get operation string.
	 * @return the operation string
	 */
	public Operation getOperation() {
		return header.getOperation();
	}

	/**
	 * Get payload of IDChain Request.
	 *
	 * @return the payload string
	 */
	public String getPayload() {
		return payload;
	}

	protected void setPayload(String payload) {
		this.payload = payload;
	}

	/**
	 * Get the proof object of the IDChainRequest.
	 *
	 * @return the proof object
	 */
	public Proof getProof() {
		return proof;
	}

	protected void setProof(Proof proof) {
		this.proof = proof;
	}

	protected byte[][] getSigningInputs() {
		String prevtxid = getOperation() == Operation.UPDATE ? header.getPreviousTxid() : "";
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

	protected abstract DIDDocument getSignerDocument() throws DIDResolveException;

	// Helper method for DIDTransaction
	protected void sanitizeHelper() throws MalformedIDChainRequestException {
		try {
			sanitize(true);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedIDChainRequestException)
				throw (MalformedIDChainRequestException)e;
			else
				throw new MalformedIDChainRequestException(e);
		}
	}

	/**
	 * Judge whether the IDChain Request is valid or not.
	 *
	 * @return the returned value is true if IDChain Request is valid;
	 *         the returned value is false if IDChain Request is not valid.
	 * @throws DIDTransactionException there is no invalid key.
	 * @throws
	 */
	public boolean isValid() throws DIDResolveException {
		DIDURL signKey = proof.getVerificationMethod();

		DIDDocument doc = getSignerDocument();
		if (doc == null)
			return false;

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

	protected static<T extends DIDEntity<?>> T parse(JsonNode content, Class<T> clazz)
			throws DIDSyntaxException {
		return DIDEntity.parse(content, clazz);
	}
}
