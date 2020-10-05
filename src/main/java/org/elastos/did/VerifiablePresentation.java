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
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.MalformedPresentationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

/**
 * A Presentation can be targeted to a specific verifier by using a Linked Data
 * Proof that includes a nonce and realm.
 *
 * This also helps prevent a verifier from reusing a verifiable presentation as
 * their own.
 */
@JsonPropertyOrder({ VerifiablePresentation.TYPE,
	VerifiablePresentation.CREATED,
	VerifiablePresentation.VERIFIABLE_CREDENTIAL,
	VerifiablePresentation.PROOF })
public class VerifiablePresentation extends DIDObject<VerifiablePresentation> {
	/**
	 * Default presentation type
	 */
	public final static String DEFAULT_PRESENTATION_TYPE = "VerifiablePresentation";

	protected final static String TYPE = "type";
	protected final static String VERIFIABLE_CREDENTIAL = "verifiableCredential";
	protected final static String CREATED = "created";
	protected final static String PROOF = "proof";
	protected final static String NONCE = "nonce";
	protected final static String REALM = "realm";
	protected final static String VERIFICATION_METHOD = "verificationMethod";
	protected final static String SIGNATURE = "signature";

	private static final Logger log = LoggerFactory.getLogger(VerifiablePresentation.class);

	@JsonProperty(TYPE)
	private String type;
	@JsonProperty(CREATED)
	private Date created;
	private Map<DIDURL, VerifiableCredential> credentials;
	@JsonProperty(VERIFIABLE_CREDENTIAL)
	private List<VerifiableCredential> _credential;
	@JsonProperty(PROOF)
	@JsonInclude(Include.NON_NULL)
	private Proof proof;

	/**
	 * The proof information for verifiable presentation.
	 *
	 * The default proof type is ECDSAsecp256r1.
	 */
	@JsonPropertyOrder({ TYPE, VERIFICATION_METHOD, REALM, NONCE, SIGNATURE })
	static public class Proof {
		@JsonProperty(TYPE)
		private String type;
		@JsonProperty(VERIFICATION_METHOD)
		@JsonSerialize(using = DIDURL.NormalizedSerializer.class)
		private DIDURL verificationMethod;
		@JsonProperty(REALM)
		private String realm;
		@JsonProperty(NONCE)
		private String nonce;
		@JsonProperty(SIGNATURE)
		private String signature;

		/**
		 * Create the proof object with the given values.
		 *
		 * @param type the type string
		 * @param method the sign key
		 * @param realm where is presentation use
		 * @param nonce the nonce string
		 * @param signature the signature string
		 */
		@JsonCreator
		protected Proof(@JsonProperty(value = TYPE) String type,
				@JsonProperty(value = VERIFICATION_METHOD, required = true) DIDURL method,
				@JsonProperty(value = REALM, required = true) String realm,
				@JsonProperty(value = NONCE, required = true) String nonce,
				@JsonProperty(value = SIGNATURE, required = true) String signature) {
			this.type = type != null ? type : Constants.DEFAULT_PUBLICKEY_TYPE;
			this.verificationMethod = method;
			this.realm = realm;
			this.nonce = nonce;
			this.signature = signature;
		}

		/**
		 * Create the proof object with the given values.
		 *
		 * @param method the sign key
		 * @param realm where is Presentation use
		 * @param nonce the nonce string
		 * @param signature the signature string
		 */
		protected Proof(DIDURL method, String realm,
				String nonce, String signature) {
			this(Constants.DEFAULT_PUBLICKEY_TYPE, method, realm, nonce, signature);
		}

		/**
		 * Get presentation type.
		 *
		 * @return the type string
		 */
	    public String getType() {
	    	return type;
	    }

	    /**
	     * Get key to sign Presentation.
	     *
	     * @return the sign key
	     */
	    public DIDURL getVerificationMethod() {
	    	return verificationMethod;
	    }

	    /**
	     * Get realm string of Presentation.
	     *
	     * @return the realm string
	     */
	    public String getRealm() {
	    	return realm;
	    }

	    /**
	     * Get nonce string of Presentation.
	     *
	     * @return the nonce string
	     */
	    public String getNonce() {
	    	return nonce;
	    }

	    /**
	     * Get signature string of Presentation.
	     *
	     * @return the signature string
	     */
	    public String getSignature() {
	    	return signature;
	    }
	}

	/**
	 * Constructs the simplest Presentation.
	 */
	protected VerifiablePresentation() {
		type = DEFAULT_PRESENTATION_TYPE;

		credentials = new TreeMap<DIDURL, VerifiableCredential>();
	}

	/**
	 * Copy constructor.
	 *
	 * @param vp the source VerifiablePresentation object.
	 */
	protected VerifiablePresentation(VerifiablePresentation vp) {
		this.type = vp.type;
		this.created = vp.created;
		this.credentials = vp.credentials;
		this._credential = vp._credential;
		this.proof = vp.proof;
	}

	/**
	 * Get the type of Presentation.
	 *
	 * @return the type string
	 */
	public String getType() {
		return type;
	}

	/**
	 * Get the time created Presentation.
	 *
	 * @return the time created
	 */
	public Date getCreated() {
		return created;
	}

	/**
	 * Get the count of Credentials in the Presentation.
	 *
	 * @return the Credentials' count
	 */
	public int getCredentialCount() {
		return credentials.size();
	}

	/**
	 * Get all Credentials in the Presentation.
	 *
	 * @return the Credential array
	 */
	public List<VerifiableCredential> getCredentials() {
		return new ArrayList<VerifiableCredential>(credentials.values());
	}

	/**
	 * Get the specified Credential.
	 *
	 * @param id the specified Credential id
	 * @return the Credential object
	 */
	public VerifiableCredential getCredential(DIDURL id) {
		if (id == null)
			throw new IllegalArgumentException();

		return credentials.get(id);
	}

	/**
	 * Get the specified Credential.
	 *
	 * @param id the specified Credential id string
	 * @return the Credential object
	 */
	public VerifiableCredential getCredential(String id) {
		DIDURL _id = id == null ? null : new DIDURL(getSigner(), id);
		return getCredential(_id);
	}

	/**
	 * Get Presentation Proof object.
	 *
	 * @return the Presentation Proof object
	 */
	public Proof getProof() {
		return proof;
	}

	/**
	 * Get signer of Presentation.
	 *
	 * @return the signer's DID
	 */
	public DID getSigner() {
		return proof.getVerificationMethod().getDid();
	}

	/**
	 * Sanitize routine before sealing or after deserialization.
	 *
	 * @param withProof check the proof object or not
	 * @throws MalformedPresentationException if the presentation object is invalid
	 */
	@Override
	protected void sanitize(boolean withProof) throws MalformedPresentationException {
		if (type == null || type.length() == 0)
			throw new MalformedPresentationException("Missing presentation type");

		if (created == null)
			throw new MalformedPresentationException("Missing presentation create timestamp");

		if (withProof && _credential != null && _credential.size() > 0) {
			for (VerifiableCredential vc : _credential) {
				try {
					vc.sanitize();
				} catch (DIDSyntaxException e) {
					throw new MalformedPresentationException(e.getMessage(), e);
				}

				if (credentials.containsKey(vc.getId()))
					throw new MalformedPresentationException("Duplicated credential id: " + vc.getId());

				credentials.put(vc.getId(), vc);
			}
		}

		this._credential = new ArrayList<VerifiableCredential>(credentials.values());

		if (withProof) {
			if (proof == null)
				throw new MalformedPresentationException("Missing presentation proof");

			if (proof.getVerificationMethod().getDid() == null)
				throw new MalformedPresentationException("Incomplete presentation verification method");
		}
	}

	/**
	 * Check whether the Presentation is genuine or not.
	 *
	 * @return whether the Credential object is genuine
	 * @throws DIDResolveException if error occurs when resolve the DID documents
	 */
	public boolean isGenuine() throws DIDResolveException {
		DID signer = getSigner();
		DIDDocument signerDoc = signer.resolve();
		if (signerDoc == null)
			return false;

		// Check the integrity of signer' document.
		if (!signerDoc.isGenuine())
			return false;

		// Unsupported public key type;
		if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE))
			return false;

		// Credential should signed by authentication key.
		if (!signerDoc.isAuthenticationKey(proof.getVerificationMethod()))
			return false;

		// All credentials should owned by signer
		for (VerifiableCredential vc : credentials.values()) {
			if (!vc.getSubject().getId().equals(signer))
				return false;

			if (!vc.isGenuine())
				return false;
		}

		VerifiablePresentation vp = new VerifiablePresentation(this);
		vp.proof = null;
		String json;
		try {
			json = vp.serialize(true);
		} catch (DIDSyntaxException ignore) {
			log.error("INTERAL - serialize presentation", ignore);
			return false;
		}

		return signerDoc.verify(proof.getVerificationMethod(),
				proof.getSignature(), json.getBytes(),
				proof.getRealm().getBytes(), proof.getNonce().getBytes());
	}

	/**
	 * Check whether the presentation is genuine or not in asynchronous mode.
	 *
	 * @return the new CompletableStage if success; null otherwise.
	 *         The boolean result is genuine or not
	 */
	public CompletableFuture<Boolean> isGenuineAsync() {
		CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
			try {
				return isGenuine();
			} catch (DIDResolveException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Check whether the presentation is valid or not.
	 *
	 * @return whether the Credential object is valid
	 * @throws DIDResolveException if error occurs when resolve the DID documents
	 */
	public boolean isValid() throws DIDResolveException {
		DID signer = getSigner();
		DIDDocument signerDoc = signer.resolve();

		// Check the validity of signer' document.
		if (!signerDoc.isValid())
			return false;

		// Unsupported public key type;
		if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE))
			return false;

		// Credential should signed by authentication key.
		if (!signerDoc.isAuthenticationKey(proof.getVerificationMethod()))
			return false;

		// All credentials should owned by signer
		for (VerifiableCredential vc : credentials.values()) {
			if (!vc.getSubject().getId().equals(signer))
				return false;

			if (!vc.isValid())
				return false;
		}

		VerifiablePresentation vp = new VerifiablePresentation(this);
		vp.proof = null;
		String json;
		try {
			json = vp.serialize(true);
		} catch (DIDSyntaxException ignore) {
			log.error("INTERAL - serialize presentation", ignore);
			return false;
		}

		return signerDoc.verify(proof.getVerificationMethod(),
				proof.getSignature(), json.getBytes(),
				proof.getRealm().getBytes(), proof.getNonce().getBytes());
	}

	/**
	 * Check whether the Credential is valid in asynchronous mode.
	 *
	 * @return the new CompletableStage if success; null otherwise.
	 * 	       The boolean result is valid or not
	 */
	public CompletableFuture<Boolean> isValidAsync() {
		CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
			try {
				return isValid();
			} catch (DIDResolveException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Parse a VerifiablePresentation object from from a string JSON
	 * representation.
	 *
	 * @param content the string JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws DIDSyntaxException if a parse error occurs
	 */
	public static VerifiablePresentation parse(String content)
			throws DIDSyntaxException {
		return parse(content, VerifiablePresentation.class);
	}

	/**
	 * Parse a VerifiablePresentation object from from a Reader object.
	 *
	 * @param src Reader object used to read JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static VerifiablePresentation parse(Reader src)
			throws DIDSyntaxException, IOException {
		return parse(src, VerifiablePresentation.class);
	}

	/**
	 * Parse a VerifiablePresentation object from from a InputStream object.
	 *
	 * @param src InputStream object used to read JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static VerifiablePresentation parse(InputStream src)
			throws DIDSyntaxException, IOException {
		return parse(src, VerifiablePresentation.class);
	}

	/**
	 * Parse a VerifiablePresentation object from from a File object.
	 *
	 * @param src File object used to read JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static VerifiablePresentation parse(File src)
			throws DIDSyntaxException, IOException {
		return parse(src, VerifiablePresentation.class);
	}

	/**
	 * Parse a VerifiablePresentation object from from a string JSON
	 * representation.
	 *
	 * @param content the string JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @deprecated use {@link #parse(String))} instead
	 */
	@Deprecated
	public static VerifiablePresentation fromJson(String content)
			throws DIDSyntaxException {
		return parse(content);
	}

	/**
	 * Parse a VerifiablePresentation object from from a Reader object.
	 *
	 * @param src Reader object used to read JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(Reader))} instead
	 */
	@Deprecated
	public static VerifiablePresentation fromJson(Reader src)
			throws DIDSyntaxException, IOException {
		return parse(src);
	}

	/**
	 * Parse a VerifiablePresentation object from from a InputStream object.
	 *
	 * @param src InputStream object used to read JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(InputStream))} instead
	 */
	@Deprecated
	public static VerifiablePresentation fromJson(InputStream src)
			throws DIDSyntaxException, IOException {
		return parse(src);
	}

	/**
	 * Parse a VerifiablePresentation object from from a File object.
	 *
	 * @param src File object used to read JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(File))} instead
	 */
	@Deprecated
	public static VerifiablePresentation fromJson(File src)
			throws DIDSyntaxException, IOException {
		return parse(src);
	}

	/**
	 * Get the Builder object to create presentation for DID.
	 *
	 * @param did the owner of Presentation.
	 * @param signKey the key to sign
	 * @param store the specified DIDStore
	 * @return the presentation Builder object
	 * @throws DIDStoreException can not load DID
	 * @throws InvalidKeyException if the signKey is invalid
	 */
	public static Builder createFor(DID did, DIDURL signKey, DIDStore store)
			throws DIDStoreException, InvalidKeyException {
		if (did == null || store == null)
			throw new IllegalArgumentException();

		DIDDocument signer = store.loadDid(did);
		if (signer == null)
			throw new DIDStoreException("Can not load DID."); // TODO: checkme!!!

		if (signKey == null) {
			signKey = signer.getDefaultPublicKey();
		} else {
			if (!signer.isAuthenticationKey(signKey))
				throw new InvalidKeyException("Not an authentication key.");
		}

		if (!signer.hasPrivateKey(signKey))
			throw new InvalidKeyException("No private key.");

		return new Builder(signer, signKey);
	}

	/**
	 * Get the Builder object to create presentation for DID.
	 *
	 * @param did the owner of the presentation
	 * @param store the specified DIDStore
	 * @return the presentation Builder object
	 * @throws DIDStoreException can not load DID
	 * @throws InvalidKeyException if the signKey is invalid
	 */
	public static Builder createFor(DID did, DIDStore store)
			throws DIDStoreException, InvalidKeyException {
		return createFor(did, null, store);
	}

	/**
     * Presentation Builder object to create presentation.
	 */
	public static class Builder {
		private DIDDocument signer;
		private DIDURL signKey;
		private String realm;
		private String nonce;
		private VerifiablePresentation presentation;

		/**
		 * Create a Builder object with issuer information.
		 *
		 * @param signer the Presentation's signer
		 * @param signKey the key to sign Presentation
		 */
		protected Builder(DIDDocument signer, DIDURL signKey) {
			this.signer = signer;
			this.signKey = signKey;
			this.presentation = new VerifiablePresentation();
		}

		/**
		 * Add Credentials to Presentation.
		 *
		 * @param credentials the credentials array
		 * @return the Presentation Builder object
		 */
		public Builder credentials(VerifiableCredential ... credentials) {
			if (presentation == null)
				throw new IllegalStateException("Presentation already sealed.");

			for (VerifiableCredential vc : credentials) {
				if (!vc.getSubject().getId().equals(signer.getSubject()))
					throw new IllegalArgumentException("Credential '" +
							vc.getId() + "' not match with requested did");

				if (presentation.credentials.containsKey(vc.getId()))
					throw new IllegalArgumentException("Credential '" +
							vc.getId() + "' already exists in the presentation");

				// TODO: integrity check?
				// if (!vc.isValid())
				//	throw new IllegalArgumentException("Credential '" +
				//			vc.getId() + "' is invalid");

				presentation.credentials.put(vc.getId(), vc);
			}

			return this;
		}

		/**
		 * Set realm for Presentation.
		 *
		 * @param realm the realm string
		 * @return the Presentation Builder object
		 */
		public Builder realm(String realm) {
			if (presentation == null)
				throw new IllegalStateException("Presentation already sealed.");

			if (realm == null || realm.isEmpty())
				throw new IllegalArgumentException();

			this.realm = realm;
			return this;
		}

		/**
		 * Set nonce for Presentation.
		 *
		 * @param nonce the nonce string
		 * @return the Presentation Builder object
		 */
		public Builder nonce(String nonce) {
			if (presentation == null)
				throw new IllegalStateException("Presentation already sealed.");

			if (nonce == null || nonce.isEmpty())
				throw new IllegalArgumentException();

			this.nonce = nonce;
			return this;
		}

		/**
		 * Seal the presentation object, attach the generated proof to the
		 * presentation.
		 *
		 * @param storepass the password for DIDStore
		 * @return the Presentation object
		 * @throws MalformedPresentationException if the presentation is invalid
		 * @throws DIDStoreException if an error occurs when access DID store
		 */
		public VerifiablePresentation seal(String storepass)
				throws MalformedPresentationException, DIDStoreException  {
			if (presentation == null)
				throw new IllegalStateException("Presentation already sealed.");

			if (storepass == null || storepass.isEmpty())
				throw new IllegalArgumentException();

			Calendar cal = Calendar.getInstance(Constants.UTC);
			presentation.created = cal.getTime();

			presentation.sanitize(false);

			String json;
			try {
				json = presentation.serialize(true);
			} catch (DIDSyntaxException e) {
				// should never happen
				// re-throw it after up-cast
				throw (MalformedPresentationException)e;
			}

			String sig = signer.sign(signKey, storepass, json.getBytes(),
					realm.getBytes(), nonce.getBytes());

			Proof proof = new Proof(signKey, realm, nonce, sig);
			presentation.proof = proof;

			// Invalidate builder
			VerifiablePresentation vp = presentation;
			this.presentation = null;

			return vp;
		}
	}
}
