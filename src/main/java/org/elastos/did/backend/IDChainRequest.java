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

import static com.google.common.base.Preconditions.checkArgument;

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
import org.elastos.did.exception.MalformedResolveResultException;
import org.elastos.did.exception.MalformedTransferTicketException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * The abstract super class for all ID chain transaction requests.
 *
 * @param <T> the type of the class modeled by this IDChainRequest object
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
	 * The IDChain Request Operations.
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

		/**
		 * Get the specification string for this operation.
		 *
		 * @return the specification string
		 */
		public String getSpecification() {
			return specification;
		}

		/**
		 * Returns the name of this enumeration constant in low case,
		 * as contained in the declaration.
		 */
		@Override
		@JsonValue
		public String toString() {
			return name().toLowerCase();
		}

		/**
		 * Returns the Status enumeration constant of the specified name.
		 * (This is a helper method for JSON deserialization)
		 *
		 * @param name the operation name
		 * @return the enumeration constant
		 */
		@JsonCreator
		public static Operation fromString(String name) {
			return valueOf(name.toUpperCase());
		}
	}

	/**
	 * Header class for the ID transaction request.
	 */
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

		/**
		 * Get the specification of this request.
		 *
		 * @return the specification string
		 */
		public String getSpecification() {
			return specification;
		}

		/**
		 * Get the operation.
		 *
		 * @return the operation of the request
		 */
		public Operation getOperation() {
			return operation;
		}

		/**
		 * Get the previous transaction id header.
		 *
		 * <p>
		 * This header item is optional. only required by the DID update request.
		 * </p>
		 *
		 * @return the previous transaction id or null if not exists
		 */
		public String getPreviousTxid() {
			return previousTxid;
		}

		/**
		 * Get the transfer ticket header.
		 *
		 * <p>
		 * This header item is optional. only required by the DID transfer request.
		 * </p>
		 *
		 * @return the transfer ticket in string format or null if not exists
		 */
		public String getTicket() {
			return ticket;
		}

		@JsonSetter(TICKET)
		private void setTicket(String ticket) {
			checkArgument(ticket != null && !ticket.isEmpty(), "Invalid ticket");

			String json = new String(Base64.decode(ticket,
					Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP));

			try {
				this.transferTicket = TransferTicket.parse(json);
			} catch (MalformedTransferTicketException e) {
				throw new IllegalArgumentException("Invalid ticket", e);
			}

			this.ticket = ticket;
		}

		/**
		 * Get the transfer ticket object from this header.
		 *
		 * @return the transfer ticket object or null if not exists
		 */
		public TransferTicket getTransferTicket()  {
			return transferTicket;
		}
	}

	/**
	 * The proof object of ID chain transaction request.
	 */
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

		/**
		 * Get the proof type string. the type is derived from the type of the
		 * public key that signed this proof.
		 *
		 * @return get proof type
		 */
		public String getType() {
			return type;
		}

		/**
		 * Get the public key id that signed this proof.
		 *
		 * @return the public key id
		 */
		public DIDURL getVerificationMethod() {
			return verificationMethod;
		}

		/**
		 * Update the verification method to a canonical DIDURL.
		 *
		 * @param ref the DID context
		 */
		protected void qualifyVerificationMethod(DID ref) {
			// TODO: need improve the impl
			if (verificationMethod.getDid() == null)
				verificationMethod = new DIDURL(ref, verificationMethod);
		}

		/**
		 * Get the signature string of this proof.
		 *
		 * @return the signature string
		 */
		public String getSignature() {
			return signature;
		}
	}

	/**
	 * Default constructor.
	 */
	protected IDChainRequest() {}

	/**
	 * Create a ID chain request with given operation.
	 *
	 * @param operation the operation
	 */
	protected IDChainRequest(Operation operation) {
		this.header = new Header(operation);
	}

	/**
	 * Create a DID update request with given previous transaction id.
	 *
	 * @param operation should be UPDATE operation
	 * @param previousTxid the previous transaction id of target DID
	 */
	protected IDChainRequest(Operation operation, String previousTxid) {
		this.header = new Header(operation, previousTxid);
	}

	/**
	 * Create a DID transfer request with given ticket.
	 *
	 * @param operation should be TRANSFER operation
	 * @param ticket the transfer ticket object
	 */
	protected IDChainRequest(Operation operation, TransferTicket ticket) {
		this.header = new Header(operation, ticket);
	}

	/**
	 * Copy constructor.
	 *
	 * @param request another ID chain request object
	 */
	protected IDChainRequest(IDChainRequest<?> request) {
		this.header = request.header;
		this.payload = request.payload;
		this.proof = request.proof;
	}

	/**
	 * Get the request header object.
	 *
	 * @return the header object
	 */
	protected Header getHeader() {
		return header;
	}

	/**
	 * Get the operation of this request.
	 *
	 * @return the operation enum
	 */
	public Operation getOperation() {
		return header.getOperation();
	}

	/**
	 * Get the payload of this ID chain request.
	 *
	 * @return the payload string
	 */
	public String getPayload() {
		return payload;
	}

	/**
	 * Set the payload for this ID chain request.
	 *
	 * @param payload the string format payload
	 */
	protected void setPayload(String payload) {
		this.payload = payload;
	}

	/**
	 * Get the proof object of this ID chain request.
	 *
	 * @return the proof object
	 */
	public Proof getProof() {
		return proof;
	}

	/**
	 * Set the proof object for the ID chain request.
	 *
	 * @param proof the proof object
	 */
	protected void setProof(Proof proof) {
		this.proof = proof;
	}

	/**
	 * Get the signing inputs for generating the proof signature.
	 *
	 * @return the array object of input byte arrays
	 */
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

	/**
	 * Abstract method to get the DIDDocument of the request signer.
	 *
	 * @return the signer's DIDDocument object
	 * @throws DIDResolveException if error occurred when resolving
	 * 		   DID document
	 */
	protected abstract DIDDocument getSignerDocument() throws DIDResolveException;

	/**
	 * Post sanitize routine after deserialization.
	 *
	 * @throws MalformedResolveResultException if the IDChainRequest
	 * 		   object is invalid
	 */
	@Override
	protected void sanitize() throws MalformedIDChainRequestException {
	}

	/**
	 * Return whether this ID chain request is valid or not.
	 *
	 * @return true if valid, otherwise false
	 * @throws DIDResolveException if if error occurred when resolving
	 * 		   DID document
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
			if (!doc.isCustomizedDid()) {
				// the signKey should be default key or authorization key
				if (!doc.getDefaultPublicKeyId().equals(signKey) &&
						doc.getAuthorizationKey(signKey) == null)
					return false;
			} else {
				// the signKey should be controller's default key
				DIDDocument controller = doc.getControllerDocument(signKey.getDid());
				if (controller == null || !controller.getDefaultPublicKeyId().equals(signKey))
					return false;
			}
		}

		return doc.verify(proof.getVerificationMethod(), proof.getSignature(),
				getSigningInputs());
	}

	/**
	 * Parse a ID chain request object from JsonNode object.
	 *
	 * @param <T> the class type of the ID chain request
	 * @param content a JsonNode object that contains a ID chain request
	 * @param clazz the class of the ID chain request
	 * @return the parsed ID chain request object
	 *
	 * @throws DIDSyntaxException if error when parse the resolve request
	 */
	protected static<T extends DIDEntity<?>> T parse(JsonNode content, Class<T> clazz)
			throws DIDSyntaxException {
		return DIDEntity.parse(content, clazz);
	}
}
