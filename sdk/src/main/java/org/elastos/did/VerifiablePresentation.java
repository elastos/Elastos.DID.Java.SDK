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
import java.net.URI;
import java.util.ArrayList;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

/**
 * A Presentation object is used to combine and present credentials.
 * They can be packaged in such a way that the authorship of the data is
 * verifiable. The data in a presentation is often all about the same
 * subject, but there is no limit to the number of subjects or issuers
 * in the presentation.
 *
 * This also helps prevent a verifier from reusing a verifiable presentation as
 * their own.
 */
@JsonPropertyOrder({ VerifiablePresentation.CONTEXT,
	VerifiablePresentation.ID,
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

	protected final static String CONTEXT = "@context";
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

	@JsonProperty(CONTEXT)
	@JsonInclude(Include.NON_EMPTY)
	List<String> context;
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
	// TODO: remove the created field in the future, use proof.created as formal time stamp
	@JsonProperty(CREATED)
	@JsonInclude(Include.NON_NULL)
	private Date created;
	@JsonProperty(VERIFIABLE_CREDENTIAL)
	private List<VerifiableCredential> _credentials;
	@JsonProperty(PROOF)
	@JsonInclude(Include.NON_NULL)
	private Proof proof;

	private Map<DIDURL, VerifiableCredential> credentials;

	private static final Logger log = LoggerFactory.getLogger(VerifiablePresentation.class);

	/**
	 * The proof information for verifiable presentation.
	 *
	 * The default proof type is ECDSAsecp256r1.
	 */
	@JsonPropertyOrder({ TYPE, CREATED, VERIFICATION_METHOD, REALM, NONCE, SIGNATURE })
	static public class Proof {
		@JsonProperty(TYPE)
		private String type;
		@JsonProperty(CREATED)
		@JsonInclude(Include.NON_NULL)
		private Date created;
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
				@JsonProperty(value = CREATED) Date created,
				@JsonProperty(value = VERIFICATION_METHOD, required = true) DIDURL method,
				@JsonProperty(value = REALM, required = true) String realm,
				@JsonProperty(value = NONCE, required = true) String nonce,
				@JsonProperty(value = SIGNATURE, required = true) String signature) {
			this.type = type != null ? type : Constants.DEFAULT_PUBLICKEY_TYPE;
			this.created = created == null ? null : new Date(created.getTime() / 1000 * 1000);
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
			this(null, method, realm, nonce, signature);
		}

		/**
		 * Create the proof object with the given values.
		 *
		 * @param created the create time stamp
		 * @param method the sign key
		 * @param realm where is Presentation use
		 * @param nonce the nonce string
		 * @param signature the signature string
		 */
		protected Proof(Date created, DIDURL method, String realm,
				String nonce, String signature) {
			this(Constants.DEFAULT_PUBLICKEY_TYPE,
					created != null ? created : Calendar.getInstance(Constants.UTC).getTime(),
					method, realm, nonce, signature);
		}

		/**
		 * Get the proof type.
		 *
		 * @return the type string
		 */
		public String getType() {
			return type;
		}

		/**
		 * Get the proof create time stamp
		 *
		 * @return the create time stamp
		 */
		public Date getCreated() {
			return created;
		}

		/**
		 * Get the verification method.
		 *
		 * @return the id of key to sign this proof
		 */
		public DIDURL getVerificationMethod() {
			return verificationMethod;
		}

		/**
		 * Get the realm string of this presentation object.
		 *
		 * @return the realm string
		 */
		public String getRealm() {
			return realm;
		}

		/**
		 * Get the nonce string of this presentation object.
		 *
		 * @return the nonce string
		 */
		public String getNonce() {
			return nonce;
		}

		/**
		 * Get signature value of this presentation object.
		 *
		 * @return the signature string
		 */
		public String getSignature() {
			return signature;
		}
	}

	/**
	 * Constructs a presentation object for given holder.
	 *
	 * @param holder the holder's DID of this presentation object
	 */
	protected VerifiablePresentation(DID holder) {
		this.holder = holder;
		credentials = new TreeMap<DIDURL, VerifiableCredential>();
	}

	/**
	 * Default constructor.
	 */
	protected VerifiablePresentation() {
		this(null);
	}

	/**
	 * Copy constructor.
	 *
	 * @param vp the source VerifiablePresentation object
	 */
	private VerifiablePresentation(VerifiablePresentation vp, boolean withProof) {
		this.context = vp.context;
		this.id = vp.id;
		this.type = vp.type;
		this.holder = vp.holder;
		this.created = vp.created;
		this.credentials = vp.credentials;
		this._credentials = vp._credentials;
		if (withProof)
			this.proof = vp.proof;
	}

	/**
	 * Get the id of this presentation object.
	 *
	 * @return the id object
	 */
	public DIDURL getId() {
		return id;
	}

	/**
	 * Get the types of this presentation object.
	 *
	 * @return an array of type string
	 */
	public List<String> getType() {
		return Collections.unmodifiableList(type);
	}

	/**
	 * Get the holder of this presentation object.
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
	 * Get the time created this presentation object.
	 *
	 * @return the create time stamp
	 */
	public Date getCreated() {
		// From 2.2.x proof.created is the formal created time stamp,
		// fail-back to created for back compatible support.
		return  proof.created != null ?  proof.created : created;
	}

	/**
	 * Get the count of Credentials in this presentation object.
	 *
	 * @return the Credentials' count
	 */
	public int getCredentialCount() {
		return credentials.size();
	}

	/**
	 * Get all Credentials in this presentation object.
	 *
	 * @return an array of all credentials
	 */
	public List<VerifiableCredential> getCredentials() {
		return Collections.unmodifiableList(_credentials);
	}

	/**
	 * Get the specified credential.
	 *
	 * @param id the specified credential id
	 * @return the credential object
	 */
	public VerifiableCredential getCredential(DIDURL id) {
		checkArgument(id != null, "Invalid credential id");

		if (id.getDid() == null)
			id = new DIDURL(getHolder(), id);

		return credentials.get(id);
	}

	/**
	 * Get the specified credential.
	 *
	 * @param id the specified credential id string
	 * @return the credential object
	 */
	public VerifiableCredential getCredential(String id) {
		return getCredential(DIDURL.valueOf(getHolder(), id));
	}

	/**
	 * Get the proof object of this presentation.
	 *
	 * @return the proof object
	 */
	public Proof getProof() {
		return proof;
	}

	/**
	 * Sanitize routine before sealing or after deserialization.
	 *
	 * @throws MalformedPresentationException if the presentation object is invalid
	 */
	@Override
	protected void sanitize() throws MalformedPresentationException {
		if (type == null || type.isEmpty())
			throw new MalformedPresentationException("Missing presentation type");

		if (proof == null)
			throw new MalformedPresentationException("Missing presentation proof");

		if (created == null && proof.created == null)
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

		if (holder == null) {
			if (id != null && id.getDid() == null)
				throw new MalformedPresentationException("Invalid presentation id");

			if (proof.getVerificationMethod().getDid() == null)
				throw new MalformedPresentationException("Invalid verification method");
		} else {
			if (id != null && id.getDid() == null)
				id.setDid(holder);

			if (proof.getVerificationMethod().getDid() == null)
				proof.getVerificationMethod().setDid(holder);
		}

		Collections.sort(type);
		_credentials = new ArrayList<VerifiableCredential>(credentials.values());
	}

	/**
	 * Check whether the presentation is genuine or not.
	 *
	 * @param listener the listener for the verification events and messages
	 * @return whether the credential object is genuine
	 * @throws DIDResolveException if error occurs when resolving the DIDs
	 */
	public boolean isGenuine(VerificationEventListener listener) throws DIDResolveException {
		DIDDocument holderDoc = getHolder().resolve();
		if (holderDoc == null) {
			if (listener != null) {
				listener.failed(this, "VP %s: can not resolve the holder's document", getId());
				listener.failed(this, "VP %s: is not genuine", getId());
			}

			return false;
		}

		// Check the integrity of holder' document.
		if (!holderDoc.isGenuine(listener)) {
			if (listener != null) {
				listener.failed(this, "VP %s: holder's document is not genuine", getId());
				listener.failed(this, "VP %s: is not genuine", getId());
			}

			return false;
		}

		// Unsupported public key type;
		if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE)) {
			if (listener != null) {
				listener.failed(this, "VP %s: key type '%s' for proof is not supported",
						getId(), proof.getType());
				listener.failed(this, "VP %s: is not genuine", getId());
			}

			return false;
		}

		// credential should signed by authentication key.
		if (!holderDoc.isAuthenticationKey(proof.getVerificationMethod())) {
			if (listener != null) {
				listener.failed(this, "VP %s: Key '%s' for proof is not an authencation key of '%s'",
						getId(), proof.getVerificationMethod(), proof.getVerificationMethod().getDid());
				listener.failed(this, "VP %s: is not genuine", getId());
			}

			return false;
		}

		// All credentials should owned by holder
		for (VerifiableCredential vc : credentials.values()) {
			if (!vc.getSubject().getId().equals(getHolder())) {
				if (listener != null) {
					listener.failed(this, "VP %s: credential '%s' not owned by the holder '%s'",
							getId(), vc.getId(), getHolder());
					listener.failed(this, "VP %s: is not genuine", getId());
				}

				return false;
			}

			if (!vc.isGenuine(listener)) {
				if (listener != null) {
					listener.failed(this, "VP %s: credential '%s' is not genuine",
							getId(), vc.getId());
					listener.failed(this, "VP %s: is not genuine", getId());
				}

				return false;
			}
		}

		VerifiablePresentation vp = new VerifiablePresentation(this, false);
		String json = vp.serialize(true);

		boolean result = holderDoc.verify(proof.getVerificationMethod(),
				proof.getSignature(), json.getBytes(),
				proof.getRealm().getBytes(), proof.getNonce().getBytes());
		if (listener != null) {
			if (result) {
				listener.succeeded(this, "VP %s: is genuine", getId());
			} else {
				listener.failed(this, "VP %s: proof is invalid, signature mismatch", getId());
				listener.failed(this, "VP %s: is not genuine", getId());
			}
		}

		return result;
	}

	/**
	 * Check whether the presentation is genuine or not.
	 *
	 * @return whether the credential object is genuine
	 * @throws DIDResolveException if error occurs when resolving the DIDs
	 */
	public boolean isGenuine() throws DIDResolveException {
		return isGenuine(null);
	}

	/**
	 * Check whether the presentation is genuine or not in asynchronous mode.
	 *
	 * @param listener the listener for the verification events and messages
	 * @return the new CompletableStage if success; null otherwise.
	 *         The boolean result is genuine or not
	 */
	public CompletableFuture<Boolean> isGenuineAsync(VerificationEventListener listener) {
		CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
			try {
				return isGenuine(listener);
			} catch (DIDResolveException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Check whether the presentation is genuine or not in asynchronous mode.
	 *
	 * @return the new CompletableStage if success; null otherwise.
	 *         The boolean result is genuine or not
	 */
	public CompletableFuture<Boolean> isGenuineAsync() {
		return isGenuineAsync(null);
	}

	/**
	 * Check whether the presentation is valid or not.
	 *
	 * @param listener the listener for the verification events and messages
	 * @return whether the credential object is valid
	 * @throws DIDResolveException if error occurs when resolve the DIDs
	 */
	public boolean isValid(VerificationEventListener listener) throws DIDResolveException {
		DIDDocument holderDoc = getHolder().resolve();
		if (holderDoc == null) {
			if (listener != null) {
				listener.failed(this, "VP %s: can not resolve the holder's document", getId());
				listener.failed(this, "VP %s: is invalid", getId());
			}

			return false;
		}

		// Check the validity of holder' document.
		if (holderDoc.isDeactivated()) {
			if (listener != null) {
				listener.failed(this, "VP %s: holder's document is deactivated", getId());
				listener.failed(this, "VP %s: is invalid", getId());
			}

			return false;
		}

		if (!holderDoc.isGenuine(listener)) {
			if (listener != null) {
				listener.failed(this, "VP %s: holder's document is not genuine", getId());
				listener.failed(this, "VP %s: is invalid", getId());
			}

			return false;
		}

		// Unsupported public key type;
		if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE)) {
			if (listener != null) {
				listener.failed(this, "VP %s: Key type '%s' for proof is not supported",
						getId(), proof.getType());
				listener.failed(this, "VP %s: is invalid", getId());
			}

			return false;
		}

		// credential should signed by authentication key.
		if (!holderDoc.isAuthenticationKey(proof.getVerificationMethod())){
			if (listener != null) {
				listener.failed(this, "VP %s: Key '%s' for proof is not an authencation key of '%s'",
						getId(), proof.getVerificationMethod(), proof.getVerificationMethod().getDid());
				listener.failed(this, "VP %s: is invalid", getId());
			}

			return false;
		}

		VerifiablePresentation vp = new VerifiablePresentation(this, false);
		String json = vp.serialize(true);

		if (!holderDoc.verify(proof.getVerificationMethod(),
				proof.getSignature(), json.getBytes(),
				proof.getRealm().getBytes(), proof.getNonce().getBytes())) {
			if (listener != null) {
				listener.failed(this, "VP %s: proof is invalid, signature mismatch", getId());
				listener.failed(this, "VP %s: is invalid", getId());
			}

			return false;
		}

		for (VerifiableCredential vc : credentials.values()) {
			// All credentials should owned by holder
			if (!vc.getSubject().getId().equals(getHolder())) {
				if (listener != null) {
					listener.failed(this, "VP %s: credential '%s' not owned by the holder '%s'",
							getId(), vc.getId(), getHolder());
					listener.failed(this, "VP %s: is not genuine", getId());
				}

				return false;
			}

			if (!vc.isValid(listener)) {
				if (listener != null) {
					listener.failed(this, "VP %s: credential '%s' is invalid",
							getId(), vc.getId());
					listener.failed(this, "VP %s: is invalid", getId());
				}

				return false;
			}
		}

		if (listener != null)
			listener.succeeded(this, "VP %s: is valid", getId());

		return true;
	}

	/**
	 * Check whether the presentation is valid or not.
	 *
	 * @return whether the credential object is valid
	 * @throws DIDResolveException if error occurs when resolve the DIDs
	 */
	public boolean isValid() throws DIDResolveException {
		return isValid(null);
	}

	/**
	 * Check whether the credential is valid in asynchronous mode.
	 *
	 * @param listener the listener for the verification events and messages
	 * @return the new CompletableStage if success.
	 * 	       The boolean result is valid or not
	 */
	public CompletableFuture<Boolean> isValidAsync(VerificationEventListener listener) {
		CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
			try {
				return isValid(listener);
			} catch (DIDResolveException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Check whether the credential is valid in asynchronous mode.
	 *
	 * @return the new CompletableStage if success.
	 * 	       The boolean result is valid or not
	 */
	public CompletableFuture<Boolean> isValidAsync() {
		return isValidAsync(null);
	}

	/**
	 * Parse a VerifiablePresentation object from a string JSON
	 * representation.
	 *
	 * @param content the string JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws MalformedPresentationException if a parse error occurs
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
	 * Parse a VerifiablePresentation object from a Reader object.
	 *
	 * @param src Reader object used to read JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws MalformedPresentationException if a parse error occurs
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
	 * Parse a VerifiablePresentation object from an InputStream object.
	 *
	 * @param src InputStream object used to read JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws MalformedPresentationException if a parse error occurs
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
	 * Parse a VerifiablePresentation object from a File object.
	 *
	 * @param src File object used to read JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws MalformedPresentationException if a parse error occurs
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
	 * Parse a VerifiablePresentation object from a string JSON
	 * representation.
	 *
	 * @param content the string JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws MalformedPresentationException if a parse error occurs
	 * @deprecated use {@link #parse(String)} instead
	 */
	@Deprecated
	public static VerifiablePresentation fromJson(String content)
			throws MalformedPresentationException {
		return parse(content);
	}

	/**
	 * Parse a VerifiablePresentation object from a Reader object.
	 *
	 * @param src Reader object used to read JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws MalformedPresentationException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(Reader)} instead
	 */
	@Deprecated
	public static VerifiablePresentation fromJson(Reader src)
			throws MalformedPresentationException, IOException {
		return parse(src);
	}

	/**
	 * Parse a VerifiablePresentation object from an InputStream object.
	 *
	 * @param src InputStream object used to read JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws MalformedPresentationException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(InputStream)} instead
	 */
	@Deprecated
	public static VerifiablePresentation fromJson(InputStream src)
			throws MalformedPresentationException, IOException {
		return parse(src);
	}

	/**
	 * Parse a VerifiablePresentation object from a File object.
	 *
	 * @param src File object used to read JSON content for building the object
	 * @return the VerifiablePresentation object
	 * @throws MalformedPresentationException if a parse error occurs
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
	 * @param store the DIDStore to load sign key
	 * @return the presentation Builder object
	 * @throws DIDStoreException if an error occurred when accessing the store
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

	/**
	 * Get the Builder object to create presentation for DID.
	 *
	 * @param did the owner of Presentation.
	 * @param signKey the key to sign
	 * @param store the DIDStore to load sign key
	 * @return the presentation Builder object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public static Builder createFor(String did, String signKey, DIDStore store)
			throws DIDStoreException {
		return createFor(DID.valueOf(did), DIDURL.valueOf(DID.valueOf(did), signKey), store);
	}

	/**
	 * Get the Builder object to create presentation for DID.
	 *
	 * @param did the owner of Presentation.
	 * @param store the DIDStore to load sign key
	 * @return the presentation Builder object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public static Builder createFor(DID did, DIDStore store)
			throws DIDStoreException {
		return createFor(did, null, store);
	}

	/**
	 * Get the Builder object to create presentation for DID.
	 *
	 * @param did the owner of Presentation.
	 * @param store the DIDStore to load sign key
	 * @return the presentation Builder object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
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
		 * Create a Builder object with given holder and sign key.
		 *
		 * @param holder the holder's DID document
		 * @param signKey the key to sign the presentation
		 */
		protected Builder(DIDDocument holder, DIDURL signKey) {
			this.holder = holder;
			this.signKey = signKey;
			this.presentation = new VerifiablePresentation(holder.getSubject());

			setDefaultType();
		}

		private void checkNotSealed() throws AlreadySealedException{
			if (presentation == null)
				throw new AlreadySealedException();
		}

		/**
		 * Set the id for the presentation.
		 *
		 * @param id the presentation id
		 * @return the Builder instance for method chaining
		 */
		public Builder id(DIDURL id) {
			checkNotSealed();
			checkArgument(id != null && (id.getDid() == null || id.getDid().equals(holder.getSubject())),
					"Invalid id");

			presentation.id = new DIDURL(holder.getSubject(), id);
			return this;
		}

		/**
		 * Set the id for the presentation.
		 *
		 * @param id the presentation id
		 * @return the Builder instance for method chaining
		 */
		public Builder id(String id) {
			return id(DIDURL.valueOf(holder.getSubject(), id));
		}

		private void setDefaultType() {
			checkNotSealed();

			if (Features.isEnabledJsonLdContext()) {
				if (presentation.context == null)
					presentation.context = new ArrayList<String>();

				if (!presentation.context.contains(VerifiableCredential.W3C_CREDENTIAL_CONTEXT))
					presentation.context.add(VerifiableCredential.W3C_CREDENTIAL_CONTEXT);

				if (!presentation.context.contains(VerifiableCredential.ELASTOS_CREDENTIAL_CONTEXT))
					presentation.context.add(VerifiableCredential.ELASTOS_CREDENTIAL_CONTEXT);
			}

			if (presentation.type == null)
				presentation.type = new ArrayList<String>();

			if (!presentation.type.contains(DEFAULT_PRESENTATION_TYPE))
				presentation.type.add(DEFAULT_PRESENTATION_TYPE);
		}

		/**
		 * Add a new presentation type.
		 *
		 * @param type the type name
		 * @param context the JSON-LD context for type, or null if not
		 * 		  enabled the JSON-LD feature
		 * @return the Builder instance for method chaining
		 */
		public Builder type(String type, String context) {
			checkNotSealed();
			checkArgument(type != null && !type.isEmpty(), "Invalid type: " + String.valueOf(type));

			if (Features.isEnabledJsonLdContext()) {
				checkArgument(context != null && !context.isEmpty(), "Invalid context: " + String.valueOf(context));

				if (presentation.context == null)
					presentation.context = new ArrayList<String>();

				if (!presentation.context.contains(context))
					presentation.context.add(context);
			} else {
				log.warn("JSON-LD context support not enabled, the context {} will be ignored", context);
			}

			if (presentation.type == null)
				presentation.type = new ArrayList<String>();

			if (!presentation.type.contains(type))
				presentation.type.add(type);

			return this;
		}

		/**
		 * Add a new presentation type.
		 *
		 * @param type the type name
		 * @param context the JSON-LD context for type, or null if not
		 * 		  enabled the JSON-LD feature
		 * @return the Builder instance for method chaining
		 */
		public Builder type(String type, URI context) {
			return type(type, context != null ? context.toString() : null);
		}

		/**
		 * Add a new presentation type.
		 *
		 * If enabled the JSON-LD feature, the type should be a full type URI:
		 *   [scheme:]scheme-specific-part#fragment,
		 * [scheme:]scheme-specific-part should be the context URL,
		 * the fragment should be the type name.
		 *
		 * Otherwise, the context URL part and # symbol could be omitted or
		 * ignored.
		 *
		 * @param type the type name
		 * @return the Builder instance for method chaining
		 */
		public Builder type(String type) {
			checkNotSealed();
			checkArgument(type != null && !type.isEmpty(), "Invalid type: " + String.valueOf(type));

			if (type.indexOf('#') < 0)
				return type(type, (String)null);
			else {
				String[] context_type = type.split("#", 2);
				return type(context_type[1], context_type[0]);
			}
		}

		/**
		 * Add a new presentation type.
		 *
		 * If enabled the JSON-LD feature, the type should be a full type URI:
		 *   [scheme:]scheme-specific-part#fragment,
		 * [scheme:]scheme-specific-part should be the context URL,
		 * the fragment should be the type name.
		 *
		 * Otherwise, the context URL part and # symbol could be omitted or
		 * ignored.
		 *
		 * @param type the type name
		 * @return the Builder instance for method chaining
		 */
		public Builder type(URI type) {
			checkNotSealed();
			checkArgument(type != null, "Invalid type: " + String.valueOf(type));

			return type(type.toString());
		}

		/**
		 * Add new presentation types.
		 *
		 * If enabled the JSON-LD feature, the type should be a full type URI:
		 *   [scheme:]scheme-specific-part#fragment,
		 * [scheme:]scheme-specific-part should be the context URL,
		 * the fragment should be the type name.
		 *
		 * Otherwise, the context URL part and # symbol could be omitted or
		 * ignored.
		 *
		 * @param types the type names
		 * @return the Builder instance for method chaining
		 */
		public Builder types(String ... types) {
			if (types == null || types.length == 0)
				return this;

			checkNotSealed();
			for (String t : types)
				type(t);

			return this;
		}

		/**
		 * Add new presentation types.
		 *
		 * If enabled the JSON-LD feature, the type should be a full type URI:
		 *   [scheme:]scheme-specific-part#fragment,
		 * [scheme:]scheme-specific-part should be the context URL,
		 * the fragment should be the type name.
		 *
		 * Otherwise, the context URL part and # symbol could be omitted or
		 * ignored.
		 *
		 * @param types the type names
		 * @return the Builder instance for method chaining
		 */
		public Builder types(URI ... types) {
			if (types == null || types.length == 0)
				return this;

			checkNotSealed();
			for (URI t : types)
				type(t);

			return this;
		}

		/**
		 * Add credentials to the new presentation object.
		 *
		 * @param credentials the credentials to be add
		 * @return the Builder instance for method chaining
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
		 * Set realm for the new presentation.
		 *
		 * @param realm the realm string
		 * @return the Builder instance for method chaining
		 */
		public Builder realm(String realm) {
			checkNotSealed();
			checkArgument(realm != null && !realm.isEmpty(), "Invalid realm");

			this.realm = realm;
			return this;
		}

		/**
		 * Set nonce for the new presentation.
		 *
		 * @param nonce the nonce string
		 * @return the Builder instance for method chaining
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
		 * @return the new presentation object
		 * @throws MalformedPresentationException if the presentation is invalid
		 * @throws DIDStoreException if an error occurs when accessing DID store
		 */
		public VerifiablePresentation seal(String storepass)
				throws MalformedPresentationException, DIDStoreException  {
			checkNotSealed();
			checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

			if (presentation.type == null || presentation.type.isEmpty())
				throw new MalformedPresentationException("Missing presentation type");

			Collections.sort(presentation.type);

			// from 2.2.x, will use proof.created as the formal created time stamp
			// keep the field for backward compatible only.
			// TODO: remove this in the future
			Calendar cal = Calendar.getInstance(Constants.UTC);
			presentation.created = cal.getTime();

			presentation._credentials = new ArrayList<VerifiableCredential>(presentation.credentials.values());

			String json = presentation.serialize(true);
			String sig = holder.sign(signKey, storepass, json.getBytes(),
					realm.getBytes(), nonce.getBytes());
			Proof proof = new Proof(presentation.created, signKey, realm, nonce, sig);
			presentation.proof = proof;

			// Invalidate builder
			VerifiablePresentation vp = presentation;
			this.presentation = null;

			return vp;
		}
	}
}
