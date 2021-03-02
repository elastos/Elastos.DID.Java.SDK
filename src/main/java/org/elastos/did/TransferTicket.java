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
import org.elastos.did.exception.MalformedDocumentException;
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
		 * @param signature the signature encoded in base64 URL safe format
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

		protected Proof(DIDURL method, String signature) {
			this(Constants.DEFAULT_PUBLICKEY_TYPE, method,
					Calendar.getInstance(Constants.UTC).getTime(), signature);
		}

		/**
		 * Get the verification method type.
		 *
		 * @return the type string
		 */
	    public String getType() {
	    	return type;
	    }

	    /**
	     * Get the verification method, normally it's a public key id.
	     *
	     * @return the sign key
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
	     * @return the signature encoded in URL safe base64 string
	     */
	    public String getSignature() {
	    	return signature;
	    }

		@Override
		public int compareTo(Proof proof) {
			int rc = (int)(this.created.getTime() - proof.created.getTime());
			if (rc == 0)
				rc = this.verificationMethod.compareTo(proof.verificationMethod);
			return rc;
		}
	}

	/**
	 * Transfer ticket constructor.
	 *
	 * @param did the subject did
	 * @param to (one of ) the new owner's DID
	 * @throws DIDResolveException if failed resolve the subject DID
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

	@JsonCreator
	protected TransferTicket(@JsonProperty(value = ID, required = true) DID did,
			@JsonProperty(value = TO, required = true) DID to,
			@JsonProperty(value = TXID, required = true) String txid) throws DIDResolveException {
		this.id = did;
		this.to = to;
		this.txid = txid;
	}

	private TransferTicket(TransferTicket ticket) {
		this.id = ticket.id;
		this.to = ticket.to;
		this.txid = ticket.txid;
		this.doc = ticket.doc;
		this.proofs = ticket.proofs;
		this._proofs = ticket._proofs;
	}

	/**
	 * Get the subject DID.
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
	 * Get first Proof object.
	 *
	 * @return the Proof object
	 */
	public Proof getProof() {
		return _proofs.get(0);
	}

	/**
	 * Get all Proof objects.
	 *
	 * @return list of the Proof objects
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
	 * Check whether the ticket is tampered or not.
	 *
	 * @return true is the ticket is genuine else false
	 */
	public boolean isGenuine() {
		DIDDocument doc = null;

		try {
			doc = getDocument();
		} catch (DIDResolveException e) {
			return false;
		}

		if (doc == null)
			return false;

		if (!doc.isGenuine())
			return false;

		// Proofs count should match with multisig
		if ((doc.getControllerCount() > 1 && proofs.size() != doc.getMultiSignature().m()) ||
				(doc.getControllerCount() <= 1 && proofs.size() != 1))
			return false;

		byte[] digest = null;
		try {
			TransferTicket tt = new TransferTicket(this);
			tt.proofs = null;
			tt._proofs = null;
			String json = tt.serialize(true);
			digest = EcdsaSigner.sha256Digest(json.getBytes());
		} catch (DIDSyntaxException ignore) {
			// Should never happen
			return false;
		}

		List<DID> checkedControllers = new ArrayList<DID>(_proofs.size());

		for (Proof proof : _proofs) {
			if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE))
				return false;

			DIDDocument controllerDoc = doc.getControllerDocument(proof.getVerificationMethod().getDid());
			if (controllerDoc == null)
				return false;

			if (!controllerDoc.isValid())
				return false;

			// if already checked this controller
			if (checkedControllers.contains(proof.getVerificationMethod().getDid()))
				return false;

			if (!proof.getVerificationMethod().equals(controllerDoc.getDefaultPublicKeyId()))
				return false;

			if (!doc.verifyDigest(proof.getVerificationMethod(), proof.getSignature(), digest))
				return false;

			checkedControllers.add(proof.getVerificationMethod().getDid());
		}

		return true;
	}

	/**
	 * Check whether the ticket is genuine and still valid to use.
	 *
	 * @return true is the ticket is valid else false
	 */
	public boolean isValid() throws DIDResolveException {
		if (!getDocument().isValid())
			return false;

		if (!isGenuine())
			return false;

		if (!txid.equals(getDocument().getMetadata().getTransactionId()))
			return false;

		return true;
	}

	/**
	 * Check whether the ticket is qualified.
	 * Qualified check will only check the number of signatures meet the
	 * requirement.
	 *
	 * @return true is the ticket is qualified else false
	 */
	public boolean isQualified() {
		if (proofs == null || proofs.isEmpty())
			return false;

		try {
			DIDDocument.MultiSignature multisig = getDocument().getMultiSignature();
			return proofs.size() == (multisig == null ? 1 : multisig.m());
		} catch (DIDResolveException e) {
			return false;
		}
	}

	/**
	 * Sanitize routine before sealing or after deserialization.
	 *
	 * @param withProof check the proof object or not
	 * @throws MalformedDocumentException if the document object is invalid
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

	protected void seal(DIDDocument controller, String storepass)
			throws DIDStoreException {
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

		DIDURL signKey = controller.getDefaultPublicKeyId();
		if (proofs == null) {
			proofs = new HashMap<DID, Proof>();
		} else {
			if (proofs.containsKey(signKey.getDid()))
				throw new AlreadySignedException(signKey.getDid().toString());
		}

		_proofs = null;

		try {
			String json = serialize(true);
			String sig = controller.sign(storepass, json.getBytes());
			Proof proof = new Proof(signKey, sig);
			proofs.put(proof.getVerificationMethod().getDid(), proof);
		} catch (DIDSyntaxException ignore) {
			// should never happen
		}

		this._proofs = new ArrayList<Proof>(proofs.values());
		Collections.sort(this._proofs);
	}

	/**
	 * Parse a TransferTicket object from from a string JSON representation.
	 *
	 * @param content the string JSON content for building the object.
	 * @return the TransferTicket object.
	 * @throws DIDSyntaxException if a parse error occurs.
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
	 * Parse a TransferTicket object from from a Reader object.
	 *
	 * @param src Reader object used to read JSON content for building the object
	 * @return the TransferTicket object
	 * @throws DIDSyntaxException if a parse error occurs
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
	 * Parse a TransferTicket object from from a InputStream object.
	 *
	 * @param src InputStream object used to read JSON content for building the object
	 * @return the TransferTicket object
	 * @throws DIDSyntaxException if a parse error occurs
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
	 * Parse a TransferTicket object from from a File object.
	 *
	 * @param src File object used to read JSON content for building the object
	 * @return the TransferTicket object
	 * @throws DIDSyntaxException if a parse error occurs
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
	 * Parse a TransferTicket object from from a string JSON representation.
	 *
	 * @param content the string JSON content for building the object
	 * @return the TransferTicket object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @deprecated use {@link #parse(String)} instead
	 */
	@Deprecated
	public static TransferTicket fromJson(String content) throws MalformedTransferTicketException {
		return parse(content);
	}

	/**
	 * Parse a TransferTicket object from from a Reader object.
	 *
	 * @param src Reader object used to read JSON content for building the object
	 * @return the TransferTicket object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(Reader)} instead
	 */
	@Deprecated
	public static TransferTicket fromJson(Reader src)
			throws MalformedTransferTicketException, IOException {
		return parse(src);
	}

	/**
	 * Parse a TransferTicket object from from a InputStream object.
	 *
	 * @param src InputStream object used to read JSON content for building the object
	 * @return the TransferTicket object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(InputStream)} instead
	 */
	@Deprecated
	public static TransferTicket fromJson(InputStream src)
			throws MalformedTransferTicketException, IOException {
		return parse(src);
	}

	/**
	 * Parse a TransferTicket object from from a File object.
	 *
	 * @param src File object used to read JSON content for building the object
	 * @return the TransferTicket object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(File)} instead
	 */
	@Deprecated
	public static TransferTicket fromJson(File src)
			throws MalformedTransferTicketException, IOException {
		return parse(src);
	}
}
