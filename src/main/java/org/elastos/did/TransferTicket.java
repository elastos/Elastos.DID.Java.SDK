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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import org.elastos.did.crypto.EcdsaSigner;
import org.elastos.did.exception.AlreadySignedException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.MalformedTransferTicketException;
import org.elastos.did.exception.NoEffectiveControllerException;
import org.elastos.did.exception.NotControllerException;
import org.elastos.did.exception.NotCustomizedDIDException;
import org.elastos.did.exception.UnknownInternalException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * Transfer ticket class.
 *
 * When customized DID owner(s) transfer the DID ownership to the others,
 * they need create and sign a transfer ticket, it the DID document is mulisig
 * document, the ticket should also multi-signed according the DID document.
 *
 * The new owner(s) can use this ticket create a transfer transaction, get
 * the subject DID's ownership.
 */
@JsonPropertyOrder({ TransferTicket.ID, TransferTicket.TO,
	TransferTicket.TXID, TransferTicket.PROOF })
public class TransferTicket extends DIDEntity<TransferTicket> {
	protected final static String ID = "id";
	protected final static String TO = "to";
	protected final static String TXID = "txid";
	protected final static String PROOF = "proof";
	protected final static String TYPE = "type";
	protected final static String VERIFICATION_METHOD = "verificationMethod";
	protected final static String CREATED = "created";
	protected final static String SIGNATURE = "signature";

	@JsonProperty(ID)
	private DID id;
	private DIDDocument doc;

	@JsonProperty(TO)
	private DID to;

	@JsonProperty(TXID)
	private String txid;

	@JsonProperty(PROOF)
	@JsonInclude(Include.NON_EMPTY)
	@JsonFormat(with = {JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY,
			JsonFormat.Feature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
	private List<Proof> _proofs;

	private HashMap<DID, Proof> proofs;

	/**
	 * The proof information for DID transfer ticket.
	 *
	 * The default proof type is ECDSAsecp256r1.
	 */
	@JsonPropertyOrder({ TYPE, CREATED, VERIFICATION_METHOD, SIGNATURE })
	static public class Proof implements Comparable<Proof> {
		@JsonProperty(TYPE)
		private String type;
		@JsonProperty(CREATED)
		@JsonInclude(Include.NON_NULL)
		private Date created;
		@JsonProperty(VERIFICATION_METHOD)
		private DIDURL verificationMethod;
		@JsonProperty(SIGNATURE)
		private String signature;

		/**
		 * Constructs the Proof object with the given values.
		 *
		 * @param type the verification method type
		 * @param method the verification method, normally it's a public key
		 * @param created the create timestamp
		 * @param signature the signature encoded in base64(URL safe)format
		 */
		@JsonCreator
		protected Proof(@JsonProperty(value = TYPE) String type,
				@JsonProperty(value = VERIFICATION_METHOD, required = true) DIDURL method,
				@JsonProperty(value = CREATED) Date created,
				@JsonProperty(value = SIGNATURE, required = true) String signature) {
			this.type = type != null ? type : Constants.DEFAULT_PUBLICKEY_TYPE;
			this.created = created == null ? null : new Date(created.getTime() / 1000 * 1000);
			this.verificationMethod = method;
			this.signature = signature;
		}

		/**
		 * Constructs the Proof object with the given values.
		 *
		 * @param method the verification method, normally it's a public key
		 * @param signature the signature encoded in base64(URL safe)format
		 */
		protected Proof(DIDURL method, String signature) {
			this(Constants.DEFAULT_PUBLICKEY_TYPE, method,
					Calendar.getInstance(Constants.UTC).getTime(), signature);
		}

		/**
		 * Get the verification method type.
		 *
		 * @return the verification method type string
		 */
		public String getType() {
			return type;
		}

		/**
		 * Get the verification method, normally it's a public key id.
		 *
		 * @return the verification method id
		 */
		public DIDURL getVerificationMethod() {
			return verificationMethod;
		}

		/**
		 * Get the created timestamp.
		 *
		 * @return the created date
		 */
		public Date getCreated() {
			return created;
		}

		/**
		 * Get the signature.
		 *
		 * @return the signature encoded in base64(URL safe) string
		 */
		public String getSignature() {
			return signature;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public int compareTo(Proof proof) {
			int rc = (int)(this.created.getTime() - proof.created.getTime());
			if (rc == 0)
				rc = this.verificationMethod.compareTo(proof.verificationMethod);
			return rc;
		}
	}

	/**
	 * Create a TransferTicket for the target DID.
	 *
	 * @param did the target did document object
	 * @param to (one of) the new owner's DID
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 */
	protected TransferTicket(DIDDocument target, DID to) throws DIDResolveException {
		checkArgument(target != null, "Invalid target DID document");
		checkArgument(to != null, "Invalid to DID");

		if (!target.isCustomizedDid())
			throw new NotCustomizedDIDException(target.getSubject().toString());

		target.getMetadata().setTransactionId(target.getSubject().resolve().getMetadata().getTransactionId());

		this.id = target.getSubject();
		this.doc = target;

		this.to = to;
		this.txid = target.getMetadata().getTransactionId();
	}

	/**
	 * Create a TransferTicket instance with the given fields.
	 *
	 * @param did the target DID object
	 * @param to (one of) the new owner's DID
	 * @param txid the latest transaction id of the target DID
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 */
	@JsonCreator
	protected TransferTicket(@JsonProperty(value = ID, required = true) DID did,
			@JsonProperty(value = TO, required = true) DID to,
			@JsonProperty(value = TXID, required = true) String txid) throws DIDResolveException {
		this.id = did;
		this.to = to;
		this.txid = txid;
	}

	/**
	 * Copy constructor.
	 *
	 * @param ticket the source object
	 * @param withProof if copy with the proof objects
	 */
	private TransferTicket(TransferTicket ticket, boolean withProof) {
		this.id = ticket.id;
		this.to = ticket.to;
		this.txid = ticket.txid;
		this.doc = ticket.doc;
		if (withProof) {
			this.proofs = ticket.proofs;
			this._proofs = ticket._proofs;
		}
	}

	/**
	 * Get the target DID of this ticket.
	 *
	 * @return subject DID object
	 */
	public DID getSubject() {
		return id;
	}

	/**
	 * Get the new owner's DID.
	 *
	 * @return the new owner's DID object
	 */
	public DID getTo() {
		return to;
	}

	/**
	 * The reference transaction ID for this transfer operation.
	 *
	 * @return reference transaction ID string
	 */
	public String getTransactionId() {
		return txid;
	}

	/**
	 * Get the first Proof object.
	 *
	 * @return the Proof object
	 */
	public Proof getProof() {
		return _proofs.get(0);
	}

	/**
	 * Get all Proof objects.
	 *
	 * @return a list of the Proof objects
	 */
	public List<Proof> getProofs() {
		return Collections.unmodifiableList(_proofs);
	}

	private DIDDocument getDocument() throws DIDResolveException {
		if (doc == null)
			doc = id.resolve();

		return doc;
	}

	/**
	 * Check whether the ticket is genuine or not.
	 *
	 * @param listener the listener for the verification events and messages
	 * @return true is the ticket is genuine else false
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 */
	public boolean isGenuine(VerificationEventListener listener) throws DIDResolveException {
		DIDDocument doc = getDocument();
		if (doc == null) {
			if (listener != null) {
				listener.failed(this, "Ticket %s: can not resolve the owner document", this.getSubject());
				listener.failed(this, "Ticket %s: is not genuine", this.getSubject());
			}

			return false;
		}

		if (!doc.isGenuine(listener)) {
			if (listener != null) {
				listener.failed(this, "Ticket %s: the owner document is not genuine", this.getSubject());
				listener.failed(this, "Ticket %s: is not genuine", this.getSubject());
			}

			return false;
		}

		// Proofs count should match with multisig
		if ((doc.getControllerCount() > 1 && proofs.size() != doc.getMultiSignature().m()) ||
				(doc.getControllerCount() <= 1 && proofs.size() != 1)) {
			if (listener != null) {
				listener.failed(this, "Ticket %s: proof size not matched with multisig, %d expected, actual is %d",
						this.getSubject(), doc.getMultiSignature().m(), proofs.size());
				listener.failed(this, "Ticket %s: is not genuine", this.getSubject());
			}

			return false;
		}

		TransferTicket tt = new TransferTicket(this, false);
		String json = tt.serialize(true);
		byte[] digest = EcdsaSigner.sha256Digest(json.getBytes());

		for (Proof proof : _proofs) {
			if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE)) {
				if (listener != null) {
					listener.failed(this, "Ticket %s: key type '%s' for proof is not supported",
							this.getSubject(), proof.getType());
					listener.failed(this, "Ticket %s: is not genuine", this.getSubject());
				}

				return false;
			}

			DIDDocument controllerDoc = doc.getControllerDocument(proof.getVerificationMethod().getDid());
			if (controllerDoc == null) {
				if (listener != null) {
					listener.failed(this, "Ticket %s: can not resolve the document for controller '%s' to verify the proof",
							this.getSubject(), proof.getVerificationMethod().getDid());
					listener.failed(this, "Ticket %s: is not genuine", this.getSubject());
				}

				return false;
			}

			if (!controllerDoc.isValid(listener)) {
				if (listener != null) {
					listener.failed(this, "Ticket %s: controller '%s' is invalid, failed to verify the proof",
							this.getSubject(), proof.getVerificationMethod().getDid());
					listener.failed(this, "Ticket %s: is not genuine", this.getSubject());
				}

				return false;
			}

			if (!proof.getVerificationMethod().equals(controllerDoc.getDefaultPublicKeyId())) {
				if (listener != null) {
					listener.failed(this, "Ticket %s: key '%s' for proof is not default key of '%s'",
							this.getSubject(), proof.getVerificationMethod(), proof.getVerificationMethod().getDid());
					listener.failed(this, "Ticket %s: is not genuine", this.getSubject());
				}

				return false;
			}

			if (!doc.verifyDigest(proof.getVerificationMethod(), proof.getSignature(), digest)) {
				if (listener != null) {
					listener.failed(this, "Ticket %s: proof '%s' is invalid, signature mismatch",
							this.getSubject(), proof.getVerificationMethod());
					listener.failed(this, "Ticket %s: is not genuine", this.getSubject());
				}

				return false;
			}
		}


		if (listener != null)
			listener.succeeded(this, "Ticket %s: is genuine", this.getSubject());

		return true;
	}

	/**
	 * Check whether the ticket is genuine or not.
	 *
	 * @return true is the ticket is genuine else false
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 */
	public boolean isGenuine() throws DIDResolveException {
		return isGenuine(null);
	}

	/**
	 * Check whether the ticket is genuine and valid to use.
	 *
	 * @param listener the listener for the verification events and messages
	 * @return true is the ticket is valid else false
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 */
	public boolean isValid(VerificationEventListener listener) throws DIDResolveException {
		DIDDocument doc = getDocument();
		if (doc == null) {
			if (listener != null) {
				listener.failed(this, "Ticket %s: can not resolve the owners document", this.getSubject());
				listener.failed(this, "Ticket %s: is not valid", this.getSubject());
			}

			return false;
		}

		if (!doc.isValid(listener)) {
			if (listener != null) {
				listener.failed(this, "Ticket %s: the owners document is not valid", this.getSubject());
				listener.failed(this, "Ticket %s: is not valid", this.getSubject());
			}

			return false;
		}

		if (!isGenuine(listener)) {
			if (listener != null)
				listener.failed(this, "Ticket %s: is not valid", this.getSubject());

			return false;
		}

		if (!txid.equals(doc.getMetadata().getTransactionId())) {
			if (listener != null) {
				listener.failed(this, "Ticket %s: the transaction id already out date", this.getSubject());
				listener.failed(this, "Ticket %s: is not valid", this.getSubject());
			}

			return false;
		}

		if (listener != null)
			listener.succeeded(this, "Ticket %s: is valid", this.getSubject());

		return true;
	}

	/**
	 * Check whether the ticket is genuine and valid to use.
	 *
	 * @return true is the ticket is valid else false
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 */
	public boolean isValid() throws DIDResolveException {
		return isValid(null);
	}

	/**
	 * Check whether the ticket is qualified.
	 *
	 * <p>
	 * Qualified check will only check the number of signatures whether matched
	 * with the multisig property of the target DIDDocument.
	 *</p>
	 *
	 * @return true is the ticket is qualified else false
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 */
	public boolean isQualified() throws DIDResolveException {
		if (proofs == null || proofs.isEmpty())
			return false;

		DIDDocument.MultiSignature multisig = getDocument().getMultiSignature();
		return proofs.size() == (multisig == null ? 1 : multisig.m());
	}

	/**
	 * Sanitize routine before sealing or after deserialization.
	 *
	 * @throws MalformedTransferTicketException if the ticket object is invalid
	 */
	@Override
	protected void sanitize() throws MalformedTransferTicketException {
		if (_proofs == null || _proofs.isEmpty())
			throw new MalformedTransferTicketException("Missing ticket proof");

		// CAUTION: can not resolve the target document here!
		//          will cause recursive resolve.

		proofs = new HashMap<DID, Proof>();

		for (Proof proof : _proofs) {
			if (proof.getVerificationMethod() == null) {
				throw new MalformedTransferTicketException("Missing verification method");
			} else {
				if (proof.getVerificationMethod().getDid() == null)
					throw new MalformedTransferTicketException("Invalid verification method");
			}

			if (proofs.containsKey(proof.getVerificationMethod().getDid()))
				throw new MalformedTransferTicketException("Aleady exist proof from " + proof.getVerificationMethod().getDid());

			proofs.put(proof.getVerificationMethod().getDid(), proof);
		}

		this._proofs = new ArrayList<Proof>(proofs.values());
		Collections.sort(this._proofs);
	}

	/**
	 * Seal this TransferTicket object with given controller.
	 *
	 * @param controller the DID controller who seal the ticket object
	 * @param storepass the password of DIDStore
	 * @throws DIDStoreException if an error occurred when access the DIDStore
	 */
	protected void seal(DIDDocument controller, String storepass)
			throws DIDStoreException {
		try {
			if (isQualified())
				return;

			if (controller.isCustomizedDid()) {
				if (controller.getEffectiveController() == null)
					throw new NoEffectiveControllerException(controller.getSubject().toString());
			} else {
				try {
					if (!getDocument().hasController(controller.getSubject()))
						throw new NotControllerException(controller.getSubject().toString());
				} catch (DIDResolveException e) {
					// Should never happen
					throw new UnknownInternalException(e);
				}
			}
		} catch (DIDResolveException ignore) {
			throw new UnknownInternalException(ignore);
		}

		DIDURL signKey = controller.getDefaultPublicKeyId();
		if (proofs == null) {
			proofs = new HashMap<DID, Proof>();
		} else {
			if (proofs.containsKey(signKey.getDid()))
				throw new AlreadySignedException(signKey.getDid().toString());
		}

		_proofs = null;

		String json = serialize(true);
		String sig = controller.sign(storepass, json.getBytes());
		Proof proof = new Proof(signKey, sig);
		proofs.put(proof.getVerificationMethod().getDid(), proof);

		this._proofs = new ArrayList<Proof>(proofs.values());
		Collections.sort(this._proofs);
	}

	/**
	 * Parse the TransferTicket object from a string JSON representation.
	 *
	 * @param content the string representation of the ticket object
	 * @return the TransferTicket object.
	 * @throws MalformedTransferTicketException if a parse error occurs
	 */
	public static TransferTicket parse(String content) throws MalformedTransferTicketException {
		try {
			return parse(content, TransferTicket.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedTransferTicketException)
				throw (MalformedTransferTicketException)e;
			else
				throw new MalformedTransferTicketException(e);
		}
	}

	/**
	 * Parse the TransferTicket object from from a Reader object.
	 *
	 * @param src the reader object to deserialize the ticket object
	 * @return the TransferTicket object
	 * @throws MalformedTransferTicketException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static TransferTicket parse(Reader src)
			throws MalformedTransferTicketException, IOException {
		try {
			return parse(src, TransferTicket.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedTransferTicketException)
				throw (MalformedTransferTicketException)e;
			else
				throw new MalformedTransferTicketException(e);
		}
	}

	/**
	 * Parse the TransferTicket object from from an InputStream object.
	 *
	 * @param src the InputStream object to deserialize the ticket object
	 * @return the TransferTicket object
	 * @throws MalformedTransferTicketException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static TransferTicket parse(InputStream src)
			throws MalformedTransferTicketException, IOException {
		try {
			return parse(src, TransferTicket.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedTransferTicketException)
				throw (MalformedTransferTicketException)e;
			else
				throw new MalformedTransferTicketException(e);
		}
	}

	/**
	 * Parse the TransferTicket object from from a File object.
	 *
	 * @param src the File object to deserialize the ticket object
	 * @return the TransferTicket object
	 * @throws MalformedTransferTicketException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static TransferTicket parse(File src)
			throws MalformedTransferTicketException, IOException {
		try {
			return parse(src, TransferTicket.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedTransferTicketException)
				throw (MalformedTransferTicketException)e;
			else
				throw new MalformedTransferTicketException(e);
		}
	}

	/**
	 * Parse the TransferTicket object from a string JSON representation.
	 *
	 * @param content the string representation of the ticket object
	 * @return the TransferTicket object.
	 * @throws MalformedTransferTicketException if a parse error occurs
	 * @deprecated use {@link #parse(String)} instead
	 */
	@Deprecated
	public static TransferTicket fromJson(String content) throws MalformedTransferTicketException {
		return parse(content);
	}

	/**
	 * Parse the TransferTicket object from from a Reader object.
	 *
	 * @param src the reader object to deserialize the ticket object
	 * @return the TransferTicket object
	 * @throws MalformedTransferTicketException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(Reader)} instead
	 */
	@Deprecated
	public static TransferTicket fromJson(Reader src)
			throws MalformedTransferTicketException, IOException {
		return parse(src);
	}

	/**
	 * Parse the TransferTicket object from from an InputStream object.
	 *
	 * @param src the InputStream object to deserialize the ticket object
	 * @return the TransferTicket object
	 * @throws MalformedTransferTicketException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(InputStream)} instead
	 */
	@Deprecated
	public static TransferTicket fromJson(InputStream src)
			throws MalformedTransferTicketException, IOException {
		return parse(src);
	}

	/**
	 * Parse the TransferTicket object from from a File object.
	 *
	 * @param src the File object to deserialize the ticket object
	 * @return the TransferTicket object
	 * @throws MalformedTransferTicketException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(File)} instead
	 */
	@Deprecated
	public static TransferTicket fromJson(File src)
			throws MalformedTransferTicketException, IOException {
		return parse(src);
	}
}
