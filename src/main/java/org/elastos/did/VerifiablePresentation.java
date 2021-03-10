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
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import org.elastos.did.exception.AlreadySealedException;
import org.elastos.did.exception.DIDNotFoundException;
import org.elastos.did.exception.DIDObjectAlreadyExistException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.IllegalUsageException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.MalformedCredentialException;
import org.elastos.did.exception.MalformedPresentationException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
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
@JsonPropertyOrder({ VerifiablePresentation.ID,
	VerifiablePresentation.TYPE,
	VerifiablePresentation.HOLDER,
	VerifiablePresentation.CREATED,
	VerifiablePresentation.VERIFIABLE_CREDENTIAL,
	VerifiablePresentation.PROOF })
public class VerifiablePresentation extends DIDEntity<VerifiablePresentation> {
	/**
	 * Default presentation type
	 */
	public final static String DEFAULT_PRESENTATION_TYPE = "VerifiablePresentation";

	protected final static String ID = "id";
	protected final static String TYPE = "type";
	protected final static String HOLDER = "holder";
	protected final static String VERIFIABLE_CREDENTIAL = "verifiableCredential";
	protected final static String CREATED = "created";
	protected final static String PROOF = "proof";
	protected final static String NONCE = "nonce";
	protected final static String REALM = "realm";
	protected final static String VERIFICATION_METHOD = "verificationMethod";
	protected final static String SIGNATURE = "signature";

	@JsonProperty(ID)
	@JsonInclude(Include.NON_NULL)
	private DIDURL id;
	@JsonProperty(TYPE)
	@JsonFormat(with = {JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY,
			JsonFormat.Feature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
	private List<String> type;
	@JsonProperty(HOLDER)
	@JsonInclude(Include.NON_NULL)
	private DID holder;
	@JsonProperty(CREATED)
	private Date created;
	@JsonProperty(VERIFIABLE_CREDENTIAL)
	private List<VerifiableCredential> _credentials;
	@JsonProperty(PROOF)
	@JsonInclude(Include.NON_NULL)
	private Proof proof;

	private Map<DIDURL, VerifiableCredential> credentials;

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
	protected VerifiablePresentation(DID holder) {
		this.holder = holder;
		credentials = new TreeMap<DIDURL, VerifiableCredential>();
	}

	protected VerifiablePresentation() {
		this(null);
	}

	/**
	 * Copy constructor.
	 *
	 * @param vp the source VerifiablePresentation object.
	 */
	private VerifiablePresentation(VerifiablePresentation vp, boolean withProof) {
		this.id = vp.id;
		this.type = vp.type;
		this.holder = vp.holder;
		this.created = vp.created;
		this.credentials = vp.credentials;
		this._credentials = vp._credentials;
		if (withProof)
			this.proof = vp.proof;
	}

	public DIDURL getId() {
		return id;
	}

	/**
	 * Get the type of Presentation.
	 *
	 * @return the type string
	 */
	public List<String> getType() {
		return Collections.unmodifiableList(type);
	}

	/**
	 * Get the holder of the Presentation.
	 *
	 * @return the holder's DID
	 */
	public DID getHolder() {
		// NOTICE:
		//
		// DID 2 SDK should add the holder field as a mandatory field when
		// create the presentation, at the same time should treat the holder
		// field as an optional field when parse the presentation.
		//
		// This will ensure compatibility with the presentations that
		// created by the old SDK.
		return holder != null ? holder : proof.getVerificationMethod().getDid();
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
		return Collections.unmodifiableList(_credentials);
	}

	/**
	 * Get the specified Credential.
	 *
	 * @param id the specified Credential id
	 * @return the Credential object
	 */
	public VerifiableCredential getCredential(DIDURL id) {
		checkArgument(id != null, "Invalid credential id");

		if (id.getDid() == null)
			id = new DIDURL(getHolder(), id);

		return credentials.get(id);
	}

	/**
	 * Get the specified Credential.
	 *
	 * @param id the specified Credential id string
	 * @return the Credential object
	 */
	public VerifiableCredential getCredential(String id) {
		return getCredential(DIDURL.valueOf(getHolder(), id));
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
	 * Sanitize routine before sealing or after deserialization.
	 *
	 * @param withProof check the proof object or not
	 * @throws MalformedPresentationException if the presentation object is invalid
	 */
	@Override
	protected void sanitize() throws MalformedPresentationException {
		if (type == null || type.isEmpty())
			throw new MalformedPresentationException("Missing presentation type");

		if (created == null)
			throw new MalformedPresentationException("Missing presentation create timestamp");

		if (_credentials != null && _credentials.size() > 0) {
			for (VerifiableCredential vc : _credentials) {
				try {
					vc.sanitize();
				} catch (MalformedCredentialException e) {
					throw new MalformedPresentationException("credential invalid: " + vc.getId(), e);
				}

				if (credentials.containsKey(vc.getId()))
					throw new MalformedPresentationException("Duplicated credential id: " + vc.getId());

				credentials.put(vc.getId(), vc);
			}
		}

		if (proof == null)
			throw new MalformedPresentationException("Missing presentation proof");

		if (proof.getVerificationMethod().getDid() == null)
			throw new MalformedPresentationException("Invalid verification method");

		Collections.sort(type);
		_credentials = new ArrayList<VerifiableCredential>(credentials.values());
	}

	/**
	 * Check whether the Presentation is genuine or not.
	 *
	 * @return whether the Credential object is genuine
	 * @throws DIDResolveException if error occurs when resolve the DID documents
	 */
	public boolean isGenuine() throws DIDResolveException {
		DIDDocument holderDoc = getHolder().resolve();
		if (holderDoc == null)
			return false;

		// Check the integrity of holder' document.
		if (!holderDoc.isGenuine())
			return false;

		// Unsupported public key type;
		if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE))
			return false;

		// Credential should signed by authentication key.
		if (!holderDoc.isAuthenticationKey(proof.getVerificationMethod()))
			return false;

		// All credentials should owned by holder
		for (VerifiableCredential vc : credentials.values()) {
			if (!vc.getSubject().getId().equals(getHolder()))
				return false;

			if (!vc.isGenuine())
				return false;
		}

		VerifiablePresentation vp = new VerifiablePresentation(this, false);
		String json = vp.serialize(true);

		return holderDoc.verify(proof.getVerificationMethod(),
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
		DIDDocument holderDoc = getHolder().resolve();
		if (holderDoc == null)
			return false;

		// Check the validity of holder' document.
		if (!holderDoc.isValid())
			return false;

		// Unsupported public key type;
		if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE))
			return false;

		// Credential should signed by authentication key.
		if (!holderDoc.isAuthenticationKey(proof.getVerificationMethod()))
			return false;

		// All credentials should owned by holder
		for (VerifiableCredential vc : credentials.values()) {
			if (!vc.getSubject().getId().equals(getHolder()))
				return false;

			if (!vc.isValid())
				return false;
		}

		VerifiablePresentation vp = new VerifiablePresentation(this, false);
		String json = vp.serialize(true);

		return holderDoc.verify(proof.getVerificationMethod(),
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
			throws MalformedPresentationException {
		try {
			return parse(content, VerifiablePresentation.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedPresentationException)
				throw (MalformedPresentationException)e;
			else
				throw new MalformedPresentationException(e);
		}
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
			throws MalformedPresentationException, IOException {
		try {
			return parse(src, VerifiablePresentation.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedPresentationException)
				throw (MalformedPresentationException)e;
			else
				throw new MalformedPresentationException(e);
		}
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
			throws MalformedPresentationException, IOException {
		try {
			return parse(src, VerifiablePresentation.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedPresentationException)
				throw (MalformedPresentationException)e;
			else
				throw new MalformedPresentationException(e);
		}
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
			throws MalformedPresentationException, IOException {
		try {
			return parse(src, VerifiablePresentation.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedPresentationException)
				throw (MalformedPresentationException)e;
			else
				throw new MalformedPresentationException(e);
		}
	}

	/**
	 * Parse a VerifiablePresentation object from from a string JSON
	 * representation.
	 *
	 * @param content the string JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @deprecated use {@link #parse(String)} instead
	 */
	@Deprecated
	public static VerifiablePresentation fromJson(String content)
			throws MalformedPresentationException {
		return parse(content);
	}

	/**
	 * Parse a VerifiablePresentation object from from a Reader object.
	 *
	 * @param src Reader object used to read JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(Reader)} instead
	 */
	@Deprecated
	public static VerifiablePresentation fromJson(Reader src)
			throws MalformedPresentationException, IOException {
		return parse(src);
	}

	/**
	 * Parse a VerifiablePresentation object from from a InputStream object.
	 *
	 * @param src InputStream object used to read JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(InputStream)} instead
	 */
	@Deprecated
	public static VerifiablePresentation fromJson(InputStream src)
			throws MalformedPresentationException, IOException {
		return parse(src);
	}

	/**
	 * Parse a VerifiablePresentation object from from a File object.
	 *
	 * @param src File object used to read JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(File)} instead
	 */
	@Deprecated
	public static VerifiablePresentation fromJson(File src)
			throws MalformedPresentationException, IOException {
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
			throws DIDStoreException {
		checkArgument(did != null, "Invalid did");
		checkArgument(store != null, "Invalid store");

		DIDDocument holder = store.loadDid(did);
		if (holder == null)
			throw new DIDNotFoundException(did.toString());

		if (signKey == null) {
			signKey = holder.getDefaultPublicKeyId();
		} else {
			if (!holder.isAuthenticationKey(signKey))
				throw new InvalidKeyException(signKey.toString());
		}

		if (!holder.hasPrivateKey(signKey))
			throw new InvalidKeyException("No private key: " + signKey);

		return new Builder(holder, signKey);
	}

	public static Builder createFor(String did, String signKey, DIDStore store)
			throws DIDStoreException {
		return createFor(DID.valueOf(did), DIDURL.valueOf(DID.valueOf(did), signKey), store);
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
			throws DIDStoreException {
		return createFor(did, null, store);
	}

	public static Builder createFor(String did, DIDStore store)
			throws DIDStoreException {
		return createFor(DID.valueOf(did), null, store);
	}

	/**
     * Presentation Builder object to create presentation.
	 */
	public static class Builder {
		private DIDDocument holder;
		private DIDURL signKey;
		private String realm;
		private String nonce;
		private VerifiablePresentation presentation;

		/**
		 * Create a Builder object with issuer information.
		 *
		 * @param holder the Presentation's holder
		 * @param signKey the key to sign Presentation
		 */
		protected Builder(DIDDocument holder, DIDURL signKey) {
			this.holder = holder;
			this.signKey = signKey;
			this.presentation = new VerifiablePresentation(holder.getSubject());
		}

		private void checkNotSealed() throws AlreadySealedException{
			if (presentation == null)
				throw new AlreadySealedException();
		}

		public Builder id(DIDURL id) {
			checkNotSealed();
			checkArgument(id != null && (id.getDid() == null || id.getDid().equals(holder.getSubject())),
					"Invalid id");

			presentation.id = new DIDURL(holder.getSubject(), id);
			return this;
		}

		public Builder id(String id) {
			return id(DIDURL.valueOf(holder.getSubject(), id));
		}

		/**
		 * Set Credential types.
		 *
		 * @param types the set of types
		 * @return the Builder object
		 */
		public Builder type(String ... types) {
			checkNotSealed();
			checkArgument(types != null && types.length > 0, "Invalid types");

			presentation.type = new ArrayList<String>(Arrays.asList(types));
			return this;
		}

		/**
		 * Add Credentials to Presentation.
		 *
		 * @param credentials the credentials array
		 * @return the Presentation Builder object
		 */
		public Builder credentials(VerifiableCredential ... credentials) {
			checkNotSealed();

			for (VerifiableCredential vc : credentials) {
				if (!vc.getSubject().getId().equals(holder.getSubject()))
					throw new IllegalUsageException(vc.getId().toString());

				if (presentation.credentials.containsKey(vc.getId()))
					throw new DIDObjectAlreadyExistException(vc.getId().toString());

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
			checkNotSealed();
			checkArgument(realm != null && !realm.isEmpty(), "Invalid realm");

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
			checkNotSealed();
			checkArgument(nonce != null && !nonce.isEmpty(), "Invalid nonce");

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
			checkNotSealed();
			checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

			if (presentation.type == null || presentation.type.isEmpty()) {
				presentation.type = new ArrayList<String>();
				presentation.type.add(DEFAULT_PRESENTATION_TYPE);
			} else {
				Collections.sort(presentation.type);
			}

			Calendar cal = Calendar.getInstance(Constants.UTC);
			presentation.created = cal.getTime();

			presentation._credentials = new ArrayList<VerifiableCredential>(presentation.credentials.values());

			String json = presentation.serialize(true);
			String sig = holder.sign(signKey, storepass, json.getBytes(),
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
