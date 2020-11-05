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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.elastos.did.Constants;
import org.elastos.did.DID;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDObject;
import org.elastos.did.DIDURL;
import org.elastos.did.crypto.Base64;
import org.elastos.did.exception.DIDBackendException;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDTransactionException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.MalformedIDChainRequestException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonGetter;
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
	 * The specification string of IDChain Request
	 */
	public static final String CURRENT_SPECIFICATION = "elastos/did/1.0";

	protected static final String HEADER = "header";
	protected static final String PAYLOAD = "payload";
	protected static final String PROOF = "proof";
	private static final String SPECIFICATION = "specification";
	private static final String OPERATION = "operation";
	private static final String PREVIOUS_TXID = "previousTxid";
	private static final String MULTI_SIGNATURE = "multisig";
	private static final String TYPE = "type";
	private static final String VERIFICATION_METHOD = "verificationMethod";
	private static final String SIGNATURE = "signature";

	private static final Logger log = LoggerFactory.getLogger(IDChainRequest.class);

	@JsonProperty(HEADER)
	private Header header;
	@JsonProperty(PAYLOAD)
	private String payload;

	private LinkedHashMap<DIDURL, Proof> proofs;

	private DID did;
	private DIDDocument doc;
	private DIDDocument effectiveDoc;

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

	public static class MultiSignature {
		private int m;
		private int n;

		public MultiSignature(int m, int n) {
			apply(m, n);
		}

		@JsonCreator
		public MultiSignature(String mOfN) {
			if (mOfN == null || mOfN.isEmpty())
				throw new IllegalArgumentException("Invalid multisig spec");

			String[] mn = mOfN.split(":");
			if (mn == null || mn.length != 2)
				throw new IllegalArgumentException("Invalid multisig spec");

			apply(Integer.valueOf(mn[0]), Integer.valueOf(mn[1]));
		}

		protected void apply(int m, int n) {
			if (m <= 0 || n <= 1 || m > n)
				throw new IllegalArgumentException("Invalid multisig spec");

			this.m = m;
			this.n = n;
		}

		public int m() {
			return m;
		}

		public int n() {
			return n;
		}

		@Override
		@JsonValue
		public String toString() {
			return String.format("%d:%d", m, n);
		}
	}

	@JsonPropertyOrder({ SPECIFICATION, OPERATION, PREVIOUS_TXID, MULTI_SIGNATURE })
	@JsonInclude(Include.NON_NULL)
	protected static class Header {
		@JsonProperty(SPECIFICATION)
		private String specification;
		@JsonProperty(OPERATION)
		private Operation operation;
		@JsonProperty(PREVIOUS_TXID)
		private String previousTxid;
		@JsonProperty(MULTI_SIGNATURE)
		private MultiSignature multisig;

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

		public MultiSignature getMultiSignature() {
			return multisig;
		}

		protected void setMultiSignature(int m, int n) {
			this.multisig = new MultiSignature(m, n);
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
	 * Get MultiSignature information.
	 *
	 * @return the MultiSignature object for multisig request; or null
	 */
	public MultiSignature getMultiSignature() {
		return header.getMultiSignature();
	}

	public MultiSignature getEffectiveMultiSignature() {
		// TODO: no impl
		return getMultiSignature();
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

	private DIDDocument getEffectiveDocument() throws DIDTransactionException {
		if (getOperation() == Operation.CREATE ||
				(getOperation() == Operation.UPDATE && !getDocument().hasController())) {
			return getDocument();
		} else {
			if (effectiveDoc == null) {
				try {
					 // TODO: need resolve specific tx
					effectiveDoc = getDid().resolve();
				} catch (DIDResolveException e) {
					throw new DIDTransactionException(e);
				}
			}

			return effectiveDoc;
		}
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

	@JsonGetter(PROOF)
	@JsonFormat(with = {JsonFormat.Feature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
	public List<Proof> getProofs() {
		return proofs.isEmpty() ? null : new ArrayList<Proof>(proofs.values());
	}

	@JsonSetter(PROOF)
	@JsonFormat(with = {JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY})
	protected void setProofs(List<Proof> proofs) throws MalformedIDChainRequestException {
		if (this.proofs != null)
			this.proofs.clear();

		if (proofs == null || proofs.isEmpty())
			return;

		for (Proof proof : proofs)
			addProof(proof);
	}

	private void addProof(Proof proof) throws MalformedIDChainRequestException {
		if (proofs == null)
			proofs = new LinkedHashMap<DIDURL, Proof>();

		if (proofs.containsKey(proof.getVerificationMethod()))
			throw new MalformedIDChainRequestException("Aleady exist proof from " + proof.verificationMethod);

		proofs.put(proof.verificationMethod, proof);
	}

	public boolean isQualified() {
		if (header.getMultiSignature() == null)
			return proofs.size() == 1;
		else
			return proofs.size() >= header.getMultiSignature().m();
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

			if (proofs == null || proofs.isEmpty())
				throw new MalformedIDChainRequestException("Missing proof");

			if (header.multisig == null && proofs.size() != 1)
					throw new MalformedIDChainRequestException("Proof and multisig mismatch.");

			for (Proof proof : proofs.values()) {
				if (proof.verificationMethod.getDid() == null)
					throw new MalformedIDChainRequestException("Uncanonical verification method.");
			}
		}
	}

	// Helper method for IDChainTransaction
	void sanitizeHelper() throws MalformedIDChainRequestException {
		sanitize(true);
	}

	private byte[][] getSigningInputs() {
		String prevtxid = getOperation() == Operation.UPDATE ? getPreviousTxid() : "";
		String multisig = header.getMultiSignature() != null ? header.getMultiSignature().toString() : "";

		byte[][] inputs = new byte[][] {
			header.getSpecification().getBytes(),
			header.getOperation().toString().getBytes(),
			prevtxid.getBytes(),
			multisig.getBytes(),
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
		addProof(new Proof(signKey, signature));
	}

	private void seal(DIDURL targetSignKey, DIDDocument doc,
			DIDURL signKey, String storepass)
			throws MalformedIDChainRequestException, DIDStoreException, InvalidKeyException {
		if (!doc.isAuthenticationKey(signKey))
			throw new InvalidKeyException("Not an authentication key.");

		sanitize(false);

		String signature = doc.sign(signKey, storepass, getSigningInputs());
		addProof(new Proof(targetSignKey, signature));
	}

	/**
	 * Judge whether the IDChain Request is valid or not.
	 *
	 * @return the returned value is true if IDChain Request is valid;
	 *         the returned value is false if IDChain Request is not valid.
	 * @throws DIDTransactionException there is no invalid key.
	 */
	public boolean isValid() throws DIDTransactionException {
		DIDDocument doc = getEffectiveDocument();
		MultiSignature multisig = getEffectiveMultiSignature();

		if (!doc.hasController()) {
			if (multisig != null)
				return false;

			if (proofs.size() != 1)
				return false;

			Map.Entry<DIDURL, Proof> entry = proofs.entrySet().iterator().next();
			Proof proof = entry.getValue();
			DIDURL id = proof.getVerificationMethod();

			if (!doc.isAuthenticationKey(id) && !doc.isAuthorizationKey(id))
				return false;

			return doc.verify(proof.getVerificationMethod(), proof.getSignature(), getSigningInputs());
		} else {
			if (doc.getCountrollerCount() == 1) {
				if (multisig != null)
					return false;

				if (proofs.size() != 1)
					return false;
			} else {
				if (multisig == null)
					return false;

				if (multisig.n() != doc.getCountrollerCount())
					return false;

				if (proofs.size() != multisig.n())
					return false;
			}

			for (Proof proof : proofs.values()) {
				DIDURL id = proof.getVerificationMethod();
				if (!doc.hasController(id.getDid()))
					return false;

				try {
					DIDDocument controller = id.getDid().resolve(true);
					if (!id.equals(controller.getDefaultPublicKeyId()))
						return false;

					if (!controller.verify(id, proof.getSignature(), getSigningInputs()))
						return false;
				} catch (DIDBackendException e) {
					new DIDTransactionException(e);
				}
			}

			if (getOperation() == Operation.UPDATE) {
				multisig = getMultiSignature();
				doc = getDocument();

				if (doc.getCountrollerCount() == 1) {
					if (multisig != null)
						return false;

					if (proofs.size() != 1)
						return false;
				} else {
					if (multisig == null)
						return false;

					if (multisig.n() != doc.getCountrollerCount())
						return false;

					if (proofs.size() != multisig.n())
						return false;
				}
			}

			return true;
		}
	}
}
