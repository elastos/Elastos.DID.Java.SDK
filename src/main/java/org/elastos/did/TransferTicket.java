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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.TreeSet;

import org.elastos.did.exception.AlreadySignedException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.MalformedDocumentException;
import org.elastos.did.exception.MalformedTransferTicketException;
import org.elastos.did.exception.NotControllerException;

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
public class TransferTicket extends DIDObject<TransferTicket> {
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

	private HashMap<DIDURL, Proof> proofs;
	@JsonProperty(PROOF)
	@JsonInclude(Include.NON_NULL)
	@JsonFormat(with = {JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY,
			JsonFormat.Feature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
	private List<Proof> _proofs;

	/**
	 * The proof information for DID transfer ticket.
	 *
	 * The default proof type is ECDSAsecp256r1.
	 */
	@JsonPropertyOrder({ TYPE, VERIFICATION_METHOD, CREATED, SIGNATURE })
	static public class Proof implements Comparable<Proof> {
		@JsonProperty(TYPE)
		private String type;
		@JsonProperty(VERIFICATION_METHOD)
		private DIDURL verificationMethod;
		@JsonProperty(CREATED)
		@JsonInclude(Include.NON_NULL)
		private Date created;
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
			this.verificationMethod = method;
			this.created = created;
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
	protected TransferTicket(DID did, DID to) throws DIDResolveException {
		this.id = did;
		this.doc = did.resolve(true);
		if (!doc.isCustomizedDid())
			throw new IllegalArgumentException("DID " + did + " is not a customized DID");

		this.to = to;
		this.txid = this.doc.getMetadata().getTransactionId();
	}

	@JsonCreator
	protected TransferTicket(@JsonProperty(value = ID, required = true) DID did,
			@JsonProperty(value = TO, required = true) DID to,
			@JsonProperty(value = TXID, required = true) String txid) throws DIDResolveException {
		this.id = did;
		this.to = to;
		this.txid = txid;
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
		if (_proofs == null || _proofs.isEmpty())
			return null;

		return _proofs.get(0);
	}

	/**
	 * Get all Proof objects.
	 *
	 * @return list of the Proof objects
	 */
	public List<Proof> getProofs() {
		return new ArrayList<Proof>(_proofs);
	}

	private void addProof(Proof proof) throws MalformedTransferTicketException {
		if (proofs == null)
			proofs = new HashMap<DIDURL, Proof>();

		if (proofs.containsKey(proof.getVerificationMethod()))
			throw new MalformedTransferTicketException("Aleady exist proof from " + proof.getVerificationMethod());

		proofs.put(proof.getVerificationMethod(), proof);
		this._proofs = new ArrayList<Proof>(new TreeSet<Proof>(proofs.values()));
	}

	private byte[][] getSigningInputs() {
		byte[][] inputs = new byte[][] {
			id.toString().getBytes(),
			to.toString().getBytes(),
			txid.getBytes()
		};

		return inputs;
	}

	/**
	 * Check whether the ticket is tampered or not.
	 *
	 * @return true is the ticket is genuine else false
	 */
	public boolean isGenuine() {
		if (!doc.isGenuine())
			return false;

		// Proofs count should match with multisig
		if ((doc.getControllerCount() > 1 && proofs.size() != doc.getMultiSignature().m()) ||
				(doc.getControllerCount() <= 1 && proofs.size() != 1))
			return false;

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

			if (!doc.verify(proof.getVerificationMethod(), proof.getSignature(), getSigningInputs()))
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
	public boolean isValid() {
		if (!doc.isValid())
			return false;

		if (!isGenuine())
			return false;

		if (!txid.equals(doc.getMetadata().getTransactionId()))
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
		if (_proofs == null || _proofs.isEmpty())
			return false;

		DIDDocument.MultiSignature multisig = doc.getMultiSignature();
		return _proofs.size() == (multisig == null ? 1 : multisig.m());
	}

	/**
	 * Sanitize routine before sealing or after deserialization.
	 *
	 * @param withProof check the proof object or not
	 * @throws MalformedDocumentException if the document object is invalid
	 */
	@Override
	protected void sanitize(boolean withProof) throws MalformedTransferTicketException {
		if (withProof) {
			try {
				doc = id.resolve();
			} catch (DIDResolveException e) {
				throw new  MalformedTransferTicketException("Can not resolve the subject DID");
			}

			if (_proofs == null || _proofs.isEmpty())
				throw new MalformedTransferTicketException("Missing ticket proof");

			for (Proof proof : _proofs) {
				if (proof.getVerificationMethod() == null) {
					throw new MalformedTransferTicketException("Missing verification method");
				} else {
					if (proof.getVerificationMethod().getDid() == null)
						throw new MalformedTransferTicketException("Invalid verification method");
				}

				addProof(proof);
			}
		}
	}

	protected void seal(DIDDocument controller, String storepass)
			throws NotControllerException, AlreadySignedException, DIDStoreException {
		if (controller == null || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		if (isQualified())
			return;

		if (!doc.hasController(controller.getSubject()))
			throw new NotControllerException("Not a contoller");

		DIDURL signKey = controller.getDefaultPublicKeyId();
		if (proofs != null && proofs.containsKey(signKey))
			throw new AlreadySignedException("Already signed by " + signKey.getDid());

		String sig = controller.sign(storepass, getSigningInputs());
		try {
			addProof(new Proof(signKey, sig));
		} catch (MalformedTransferTicketException ignore) {
			// should never happen
		}
	}

	/**
	 * Parse a TransferTicket object from from a string JSON representation.
	 *
	 * @param content the string JSON content for building the object.
	 * @return the TransferTicket object.
	 * @throws DIDSyntaxException if a parse error occurs.
	 */
	public static TransferTicket parse(String content) throws DIDSyntaxException {
		return parse(content, TransferTicket.class);
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
			throws DIDSyntaxException, IOException {
		return parse(src, TransferTicket.class);
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
			throws DIDSyntaxException, IOException {
		return parse(src, TransferTicket.class);
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
			throws DIDSyntaxException, IOException {
		return parse(src, TransferTicket.class);
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
	public static TransferTicket fromJson(String content) throws DIDSyntaxException {
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
			throws DIDSyntaxException, IOException {
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
			throws DIDSyntaxException, IOException {
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
			throws DIDSyntaxException, IOException {
		return parse(src);
	}

}
