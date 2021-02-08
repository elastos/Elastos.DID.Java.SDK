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
import static com.google.common.base.Preconditions.checkState;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import org.elastos.did.backend.CredentialBiography;
import org.elastos.did.backend.CredentialTransaction;
import org.elastos.did.backend.IDChainRequest;
import org.elastos.did.exception.CredentialAlreadyExistException;
import org.elastos.did.exception.CredentialExpiredException;
import org.elastos.did.exception.CredentialInvalidException;
import org.elastos.did.exception.CredentialNotGenuineException;
import org.elastos.did.exception.CredentialRevokedException;
import org.elastos.did.exception.DIDBackendException;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDInvalidException;
import org.elastos.did.exception.DIDNotFoundException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.DIDTransactionException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.MalformedCredentialException;
import org.elastos.did.exception.MalformedDIDURLException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFilter;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ser.PropertyFilter;
import com.fasterxml.jackson.databind.ser.PropertyWriter;

/**
 * VerifiableCredential is a set of one or more claims made by the same entity.
 *
 * Credential might also include an identifier and metadata to
 * describe properties of the credential.
 */
@JsonPropertyOrder({ VerifiableCredential.ID,
	VerifiableCredential.TYPE,
	VerifiableCredential.ISSUER,
	VerifiableCredential.ISSUANCE_DATE,
	VerifiableCredential.EXPIRATION_DATE,
	VerifiableCredential.CREDENTIAL_SUBJECT,
	VerifiableCredential.PROOF })
@JsonFilter("credentialFilter")
public class VerifiableCredential extends DIDObject<VerifiableCredential> implements DIDEntry {
	protected final static String ID = "id";
	protected final static String TYPE = "type";
	protected final static String ISSUER = "issuer";
	protected final static String ISSUANCE_DATE = "issuanceDate";
	protected final static String EXPIRATION_DATE = "expirationDate";
	protected final static String CREDENTIAL_SUBJECT = "credentialSubject";
	protected final static String PROOF = "proof";
	protected final static String VERIFICATION_METHOD = "verificationMethod";
	protected final static String CREATED = "created";
	protected final static String SIGNATURE = "signature";

	private static final Logger log = LoggerFactory.getLogger(VerifiableCredential.class);

	@JsonProperty(ID)
	private DIDURL id;
	@JsonProperty(TYPE)
	private String[] type;
	@JsonProperty(ISSUER)
	private DID issuer;
	@JsonProperty(ISSUANCE_DATE)
	private Date issuanceDate;
	@JsonProperty(EXPIRATION_DATE)
	@JsonInclude(Include.NON_NULL)
	private Date expirationDate;
	@JsonProperty(CREDENTIAL_SUBJECT)
	private Subject subject;
	@JsonProperty(PROOF)
	@JsonInclude(Include.NON_NULL)
	private Proof proof;

	private CredentialMetadata metadata;

	/**
     * The object keeps the credential subject contents.
     *
     * This id field is mandatory, should be the contoller's DID.
     * All the other fields could be defined by the application.
     * In order to support the JSON serialization, all values should be
     * JSON serializable.
	 */
	@JsonPropertyOrder({ ID })
	static public class Subject {
		private DID id;
		private TreeMap<String, Object> properties;

		/**
		 * Constructs the CredentialSubject object with given controller.
		 *
		 * @param id the controller of Credential Subject
		 */
		@JsonCreator
		protected Subject(@JsonProperty(value = ID) DID id) {
			this.id = id;
			this.properties = new TreeMap<String, Object>();
		}

		/**
		 * Get the controller.
		 *
		 * @return the controller's DID
		 */
		@JsonGetter(ID)
		public DID getId() {
			return id;
		}

		/**
		 * Set the controller.
		 *
		 * @param did the controller's DID
		 */
		protected void setId(DID did) {
			this.id = did;
		}

		/**
		 * Helper getter method for properties serialization.
		 * NOTICE: Should keep the alphabetic serialization order.
		 *
		 * @return a String to Object map include all application defined
		 *         properties
		 */
		@JsonAnyGetter
		@JsonPropertyOrder(alphabetic = true)
		private Map<String, Object> _getProperties() {
			return properties;
		}

		/**
		 * Helper setter method for properties deserialization.
		 *
		 * @param name the property name
		 * @param value the property value
		 */
		@JsonAnySetter
		private void setProperty(String name, Object value) {
			if (name.equals(ID))
				return;

			properties.put(name, value);
		}

		/**
		 * Get the subject properties.
		 *
		 * @return the properties in String to Object map. It's a read-only map
		 */
		public Map<String, Object> getProperties() {
			// TODO: make it unmodifiable recursively
			 return Collections.unmodifiableMap(properties);
		}

		/**
		 * Get the count of properties.
		 *
		 * @return the fields count
		 */
		public int getPropertyCount() {
			return properties.size();
		}

		/**
		 * Get the specified property.
		 *
		 * @param name the property name
		 * @return the property value
		 */
		public Object getProperty(String name) {
			return properties.get(name);
		}

		/**
		 * Get properties as a JSON string.
		 *
		 * @return the JSON string
		 */
		public String getPropertiesAsString() {
			try {
				return getObjectMapper().writeValueAsString(properties);
			} catch (JsonProcessingException ignore) {
				log.error("INTERNAL - Serialize credential subject", ignore);
				return null;
			}
		}
	}

	/**
	 * The proof information for verifiable credential.
	 *
	 * The default proof type is ECDSAsecp256r1.
	 */
	@JsonPropertyOrder({ TYPE, CREATED, VERIFICATION_METHOD, SIGNATURE })
	@JsonFilter("credentialProofFilter")
	static public class Proof {
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

		protected static PropertyFilter getFilter() {
			return new DIDPropertyFilter() {
				@Override
				protected boolean include(PropertyWriter writer, Object pojo, SerializeContext context) {
					if (context.isNormalized())
						return true;

					Proof proof = (Proof)pojo;
					switch (writer.getName()) {
					case TYPE:
						return !(proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE));

					default:
						return true;
					}
				}
			};
		}

	}

	/**
	 * Default constructor.
	 */
	protected VerifiableCredential() {
	}

	/**
	 * Constructs a credential object, copy the contents from the given object.
	 *
	 * @param vc the source credential object
	 */
	protected VerifiableCredential(VerifiableCredential vc) {
		this.id = vc.id;
		this.type = vc.type;
		this.issuer = vc.issuer;
		this.issuanceDate = vc.issuanceDate;
		this.expirationDate = vc.expirationDate;
		this.subject = vc.subject;
		this.proof = vc.proof;
	}

	/**
	 * Get the credential id.
	 *
	 * @return the identifier
	 */

	@Override
	public DIDURL getId() {
		return id;
	}

	/**
	 * Get the credential type.
	 *
	 * @return the type array
	 */
	@Override
	public String[] getType() {
		// Make a copy
		return Arrays.copyOf(type, type.length);
	}

	/**
	 * Type setter for deserialization.
	 *
	 * Should sort the types in alphabet order when setting the credential type.
	 *
	 * @param type the type names in String array
	 */
	@JsonSetter(TYPE)
	private void setType(String[] type) {
		if (type != null && type.length != 0) {
			this.type = Arrays.copyOf(type,  type.length);
			Arrays.sort(this.type);
		}
	}

	/**
	 * Get the credential issuer.
	 *
	 * @return the issuer's DID
	 */
	public DID getIssuer() {
		return issuer;
	}

	/**
	 * Get the issuance time.
	 *
	 * @return the issuance time
	 */
	public Date getIssuanceDate() {
		return issuanceDate;
	}

	/**
	 * Checks if there is an expiration time specified.
	 *
	 * @return whether the credential has expiration time
	 */
	protected boolean hasExpirationDate() {
		return expirationDate != null;
	}

	/**
	 * Get the expires time.
	 *
	 * @return the expires time
	 */
	public Date getExpirationDate() {
		if (expirationDate != null)
			return expirationDate;
		else {
			try {
				DIDDocument controllerDoc = subject.id.resolve();
				if (controllerDoc != null)
					return controllerDoc.getExpires();
			} catch (DIDBackendException e) {
				return null;
			}

			return null;
		}
	}

	/**
	 * Get last modified time.
	 *
	 * @return the last modified time, maybe null for old version vc
	 */
	public Date getLastModified() {
		return proof.getCreated();
	}

	/**
	 * Get Credential subject content.
	 *
	 * @return the Credential Subject object
	 */
	public Subject getSubject() {
		return subject;
	}

	/**
	 * Get Credential proof object.
	 *
	 * @return the Credential Proof object
	 */
	public Proof getProof() {
		return proof;
	}

	/**
	 * Sanitize routine before sealing or after deserialization.
	 *
	 * @param withProof check the proof object or not
	 * @throws MalformedCredentialException if the credential object is invalid
	 */
	@Override
	protected void sanitize(boolean withProof) throws MalformedCredentialException {
		if (id == null)
			throw new MalformedCredentialException("Missing credential id");

		if (type == null || type.length == 0)
			throw new MalformedCredentialException("Missing credential type");

		if (issuanceDate == null)
			throw new MalformedCredentialException("Missing credential issuance date");

		if (subject == null)
			throw new MalformedCredentialException("Missing credential subject");

		if (subject.id == null)
			throw new MalformedCredentialException("Missing credential subject id");

		if (withProof && proof == null)
			throw new MalformedCredentialException("Missing credential proof");

		// Update id references
		if (issuer == null)
			issuer = subject.id;

		if (id.getDid() == null)
			id.setDid(subject.id);

		if (withProof) {
			if (proof.verificationMethod.getDid() == null)
				proof.verificationMethod.setDid(issuer);
		}
	}

	/**
	 * Get current object's DID context.
	 *
	 * @return the DID object or null
	 */
	@Override
	protected DID getSerializeContextDid() {
		return getSubject().getId();
	}

	protected static PropertyFilter getFilter() {
		return new DIDPropertyFilter() {
			@Override
			protected boolean include(PropertyWriter writer, Object pojo, SerializeContext context) {
				if (context.isNormalized())
					return true;

				VerifiableCredential vc = (VerifiableCredential)pojo;
				switch (writer.getName()) {
				case ISSUER:
					return !(vc.getIssuer().equals(context.getDid()));

				default:
					return true;
				}
			}
		};
	}

	/**
	 * Set meta data for Credential.
	 *
	 * @param metadata the meta data object
	 */
	protected void setMetadata(CredentialMetadata metadata) {
		this.metadata = metadata;
		this.getId().setMetadata(metadata);
	}

	/**
	 * Get meta data object from Credential.
	 *
	 * @return the Credential Meta data object
	 */
	public CredentialMetadata getMetadata() {
		if (metadata == null)
			metadata = new CredentialMetadata(getId());

		return metadata;
	}

	private DIDStore getStore() {
		return metadata.getStore();
	}

	/**
	 * Check if the Credential is self proclaimed or not.
	 *
	 * @return whether the credential is self proclaimed
	 */
	public boolean isSelfProclaimed() {
		return issuer.equals(subject.id);
	}

	/**
	 * Check if the Credential is expired or not.
	 *
	 * @return whether the Credential object is expired
	 * @throws DIDResolveException if error occurs when resolve the DID documents
	 */
	public boolean isExpired() throws DIDResolveException {
		if (expirationDate != null) {
			Calendar now = Calendar.getInstance(Constants.UTC);

			Calendar expireDate  = Calendar.getInstance(Constants.UTC);
			expireDate.setTime(expirationDate);

			if (now.after(expireDate))
				return true;
		}

		DIDDocument controllerDoc = subject.id.resolve();
		if (controllerDoc.isExpired())
			return true;

		if (!isSelfProclaimed()) {
			DIDDocument issuerDoc = issuer.resolve();
			if (issuerDoc.isExpired())
				return true;
		}

		return false;
	}

	/**
	 * Check if the Credential is expired or not in asynchronous mode.
	 *
	 * @return the new CompletableStage if success; null otherwise.
	 *         The boolean result is expired or not
	 */
	public CompletableFuture<Boolean> isExpiredAsync() {
		CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
			try {
				return isExpired();
			} catch (DIDResolveException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Check whether the Credential is genuine or not.
	 *
	 * @return whether the Credential object is genuine
	 * @throws DIDResolveException if error occurs when resolve the DID documents
	 */
	public boolean isGenuine() throws DIDResolveException {
		if (!getId().getDid().equals(getSubject().getId()))
			return false;

		DIDDocument issuerDoc = issuer.resolve();
		if (issuerDoc == null)
			throw new DIDResolveException("Can not resolve the issuer's DID");

		// Credential should signed by any authentication key.
		if (!issuerDoc.isAuthenticationKey(proof.getVerificationMethod()))
			return false;

		// Unsupported public key type;
		if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE))
			return false; // TODO: should throw an exception?

		VerifiableCredential vc = new VerifiableCredential(this);
		vc.proof = null;
		String json;
		try {
			json = vc.serialize(true);
		} catch (DIDSyntaxException ignore) {
			log.error("INTERNAL - serialize credential", ignore);
			return false;
		}

		if (!issuerDoc.verify(proof.getVerificationMethod(),
				proof.getSignature(), json.getBytes()))
			return false;

		if (!issuerDoc.isGenuine())
			return false;

		if (!isSelfProclaimed()) {
			DIDDocument controllerDoc = subject.id.resolve();
			if (!controllerDoc.isGenuine())
				return false;
		}

		return true;
	}

	/**
	 * Check whether the Credential is genuine or not in asynchronous mode.
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

	public boolean isRevoked() throws DIDResolveException {
		// TODO: needs to improve: use the resolved status if available
		CredentialBiography bio = DIDBackend.getInstance().resolveCredentialBiography(
				getId(), getIssuer());
		return bio.getStatus() == CredentialBiography.Status.REVOKED;
	}

	public CompletableFuture<Boolean> isRevokedAsync() {
		CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
			try {
				return isRevoked();
			} catch (DIDResolveException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Check whether the Credential is valid or not.
	 *
	 * @return whether the Credential object is valid
	 * @throws DIDResolveException if error occurs when resolve the DID documents
	 */
	public boolean isValid() throws DIDResolveException {
		if (expirationDate != null) {
			Calendar now = Calendar.getInstance(Constants.UTC);

			Calendar expireDate  = Calendar.getInstance(Constants.UTC);
			expireDate.setTime(expirationDate);

			if (now.after(expireDate))
				return false;
		}

		if (isRevoked())
			return false;

		DIDDocument issuerDoc = issuer.resolve();

		// Credential should signed by any authentication key.
		if (!issuerDoc.isAuthenticationKey(proof.getVerificationMethod()))
			return false;

		// Unsupported public key type;
		if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE))
			return false; // TODO: should throw an exception.

		VerifiableCredential vc = new VerifiableCredential(this);
		vc.proof = null;
		String json;
		try {
			json = vc.serialize(true);
		} catch (DIDSyntaxException ignore) {
			log.error("INTERNAL - serialize credential", ignore);
			return false;
		}

		if (!issuerDoc.verify(proof.getVerificationMethod(),
				proof.getSignature(), json.getBytes()))
			return false;

		if (!issuerDoc.isValid())
			return false;

		if (!isSelfProclaimed()) {
			DIDDocument controllerDoc = subject.id.resolve();
			if (!controllerDoc.isValid())
				return false;
		}

		return true;

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

	public boolean wasDeclared() throws DIDResolveException {
		CredentialBiography bio = DIDBackend.getInstance().resolveCredentialBiography(
				getId(), getIssuer());

		if (bio.getStatus() == CredentialBiography.Status.NOT_FOUND)
			return false;

		for (CredentialTransaction tx : bio.getAllTransactions()) {
			if (tx.getRequest().getOperation() == IDChainRequest.Operation.DECLARE)
				return true;
		}

		return false;
	}

	public void declare(DIDURL signKey, String storepass, DIDTransactionDispatcher dispatcher)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkState(getMetadata().attachedStore(), "Not attached with a store");

		if (!isGenuine()) {
			log.error("Publish failed because the credential is not genuine.");
			throw new CredentialNotGenuineException(getId().toString());
		}

		if (isExpired()) {
			log.error("Publish failed because the credential is expired.");
			throw new CredentialExpiredException(getId().toString());
		}

		if (isRevoked()) {
			log.error("Publish failed because the credential is revoked.");
			throw new CredentialRevokedException(getId().toString());
		}

		if (wasDeclared()) {
			log.error("Publish failed because the credential already declared.");
			throw new CredentialAlreadyExistException(getId().toString());
		}

		DIDDocument owner = getStore().loadDid(getSubject().getId());
		if (owner == null) {
			// Fail-back: resolve the owner's document
			owner = getSubject().getId().resolve();
			if (owner == null)
				throw new DIDNotFoundException(getSubject().getId().toString());

			owner.getMetadata().attachStore(getStore());
		}

		checkState(signKey != null || owner.getDefaultPublicKeyId() != null, "No effective controller");

		if (signKey != null) {
			if (!owner.isAuthenticationKey(signKey))
				throw new InvalidKeyException(signKey.toString());
		} else {
			signKey = owner.getDefaultPublicKeyId();
		}

		DIDBackend.getInstance().declareCredential(this, owner, signKey, storepass, dispatcher);
	}

	public void declare(DIDURL signKey, String storepass)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		declare(signKey, storepass, null);
	}

	public void declare(String signKey, String storepass, DIDTransactionDispatcher dispatcher)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		declare(DIDURL.valueOf(getSubject().getId(), signKey), storepass, dispatcher);
	}

	public void declare(String signKey, String storepass)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		declare(DIDURL.valueOf(getSubject().getId(), signKey), storepass, null);
	}

	public void declare(String storepass, DIDTransactionDispatcher dispatcher)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		declare((DIDURL)null, storepass, dispatcher);
	}

	public void declare(String storepass)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		declare((DIDURL)null, storepass, null);
	}

	public CompletableFuture<Void> declareAsync(DIDURL signKey, String storepass,
			DIDTransactionDispatcher dispatcher) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				declare(signKey, storepass, dispatcher);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	public CompletableFuture<Void> declareAsync(DIDURL signKey, String storepass) {
		return declareAsync(signKey, storepass, null);
	}

	public CompletableFuture<Void> declareAsync(String signKey, String storepass,
			DIDTransactionDispatcher dispatcher) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				declare(signKey, storepass, dispatcher);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	public CompletableFuture<Void> declareAsync(String signKey, String storepass) {
		return declareAsync(signKey, storepass, null);
	}

	public CompletableFuture<Void> declareAsync(String storepass,
			DIDTransactionDispatcher dispatcher) {
		return declareAsync((DIDURL)null, storepass, dispatcher);
	}

	public CompletableFuture<Void> declareAsync(String storepass) {
		return declareAsync((DIDURL)null, storepass, null);
	}

	public void revoke(DIDDocument signer, DIDURL signKey, String storepass,
			DIDTransactionDispatcher dispatcher)
			throws DIDNotFoundException, InvalidKeyException, CredentialRevokedException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkState(getMetadata().attachedStore(), "Not attached with a store");

		DIDDocument owner = getSubject().getId().resolve();
		if (owner == null) {
			log.error("Publish failed because the credential owner is not published.");
			throw new DIDNotFoundException(getSubject().getId().toString());
		}
		owner.getMetadata().attachStore(getStore());

		DIDDocument issuer = getIssuer().resolve();
		if (issuer == null) {
			log.error("Publish failed because the credential issuer is not published.");
			throw new DIDNotFoundException(getIssuer().toString());
		}
		issuer.getMetadata().attachStore(getStore());

		if (isRevoked()) {
			log.error("Publish failed because the credential is revoked.");
			throw new CredentialRevokedException(getId().toString());
		}

		if (signer == null) {
			DID signerDid = (signKey != null && signKey.getDid() != null) ?
					signKey.getDid() : getSubject().getId();

			signer = getStore().loadDid(signerDid);
			if (signer == null) {
				// Fail-back: resolve the owner's document
				signer = getSubject().getId().resolve();
				if (signer == null)
					throw new DIDNotFoundException(getSubject().getId().toString());

				signer.getMetadata().attachStore(getStore());
			}
		}

		if (!signer.getSubject().equals(getSubject().getId()) &&
				!signer.getSubject().equals(getIssuer()) &&
				!owner.hasController(signer.getSubject()) &&
				!issuer.hasController(signer.getSubject())) {
			log.error("Publish failed because the invalid signer or signkey.");
			throw new InvalidKeyException("Not owner or issuer: " + signer.getSubject());
		}

		checkState(signKey != null || signer.getDefaultPublicKeyId() != null, "Unknown sign key");

		if (signKey != null) {
			if (!signer.isAuthenticationKey(signKey))
				throw new InvalidKeyException(signKey.toString());
		} else {
			signKey = signer.getDefaultPublicKeyId();
		}

		DIDBackend.getInstance().revokeCredential(this, signer, signKey, storepass, dispatcher);
	}

	public void revoke(DIDDocument signer, DIDURL signKey, String storepass)
			throws DIDNotFoundException, InvalidKeyException, CredentialRevokedException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(signer, signKey, storepass, null);
	}

	public void revoke(DIDDocument signer, String storepass, DIDTransactionDispatcher dispatcher)
			throws DIDNotFoundException, InvalidKeyException, CredentialRevokedException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(signer, (DIDURL)null, storepass, dispatcher);
	}

	public void revoke(DIDDocument signer, String storepass)
			throws DIDNotFoundException, InvalidKeyException, CredentialRevokedException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(signer, (DIDURL)null, storepass, null);
	}

	public void revoke(DIDURL signKey, String storepass, DIDTransactionDispatcher dispatcher)
			throws DIDNotFoundException, InvalidKeyException, CredentialRevokedException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(null, signKey, storepass, dispatcher);
	}

	public void revoke(DIDURL signKey, String storepass)
			throws DIDNotFoundException, InvalidKeyException, CredentialRevokedException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(null, signKey, storepass, null);
	}

	public void revoke(DIDDocument signer, String signKey, String storepass,
			DIDTransactionDispatcher dispatcher)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(signer, DIDURL.valueOf(getSubject().getId(), signKey), storepass, dispatcher);
	}

	public void revoke(DIDDocument signer, String signKey, String storepass)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(signer, signKey, storepass, null);
	}

	public void revoke(String signKey, String storepass, DIDTransactionDispatcher dispatcher)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(null, signKey, storepass, dispatcher);
	}

	public void revoke(String signKey, String storepass)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(null, signKey, storepass, null);
	}

	public void revoke(String storepass, DIDTransactionDispatcher dispatcher)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(null, (DIDURL)null, storepass, dispatcher);
	}

	public void revoke(String storepass)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(null, (DIDURL)null, storepass, null);
	}

	public CompletableFuture<Void> revokeAsync(DIDURL signKey, String storepass,
			DIDTransactionDispatcher dispatcher) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				revoke(signKey, storepass, dispatcher);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	public CompletableFuture<Void> revokeAsync(DIDURL signKey, String storepass) {
		return revokeAsync(signKey, storepass, null);
	}

	public CompletableFuture<Void> revokeAsync(String signKey, String storepass,
			DIDTransactionDispatcher dispatcher) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				revoke(signKey, storepass, dispatcher);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	public CompletableFuture<Void> revokeAsync(String signKey, String storepass) {
		return revokeAsync(signKey, storepass, null);
	}

	public CompletableFuture<Void> revokeAsync(String storepass,
			DIDTransactionDispatcher dispatcher) {
		return revokeAsync((DIDURL)null, storepass, dispatcher);
	}

	public CompletableFuture<Void> revokeAsync(String storepass) {
		return revokeAsync((DIDURL)null, storepass, null);
	}

	public static void revoke(DIDURL id, DIDDocument signer, DIDURL signKey,
			String storepass, DIDTransactionDispatcher dispatcher)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		checkArgument(id != null, "Invalid credential id");
		checkArgument(signer != null, "Invalid issuer's document");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkState(signer.getMetadata().attachedStore(), "Issuer document not attached with a store");

		CredentialBiography bio = DIDBackend.getInstance().resolveCredentialBiography(id, signer.getSubject());
		if (bio.getStatus() == CredentialBiography.Status.REVOKED) {
			log.error("Publish failed because the credential is revoked.");
			throw new CredentialRevokedException(id.toString());
		}

		if (bio.getStatus() == CredentialBiography.Status.VALID) {
			VerifiableCredential vc = bio.getTransaction(0).getRequest().getCredential();
			if (!signer.getSubject().equals(vc.getSubject().getId()) &&
					signer.getSubject().equals(vc.getIssuer())) {
				log.error("Publish failed because the invalid signer or signkey.");
				throw new InvalidKeyException("Not owner or issuer: " + signer.getSubject());
			}
		}

		checkState(signKey != null || signer.getDefaultPublicKeyId() != null, "Unknown sign key");

		if (signKey != null) {
			if (!signer.isAuthenticationKey(signKey))
				throw new InvalidKeyException(signKey.toString());
		} else {
			signKey = signer.getDefaultPublicKeyId();
		}

		DIDBackend.getInstance().revokeCredential(id, signer, signKey, storepass, dispatcher);
	}

	public static void revoke(DIDURL id, DIDDocument issuer, DIDURL signKey, String storepass)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(id, issuer, signKey, storepass, null);
	}

	public static void revoke(String id, DIDDocument issuer, String signKey,
			String storepass, DIDTransactionDispatcher dispatcher)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(DIDURL.valueOf(id), issuer, DIDURL.valueOf(issuer.getSubject(), signKey),
				storepass, dispatcher);
	}

	public static void revoke(String id, DIDDocument issuer, String signKey, String storepass)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(DIDURL.valueOf(id), issuer, DIDURL.valueOf(issuer.getSubject(), signKey),
				storepass, null);
	}

	public static void revoke(DIDURL id, DIDDocument issuer, String storepass,
			DIDTransactionDispatcher dispatcher)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(id, issuer, null, storepass, dispatcher);
	}

	public static void revoke(DIDURL id, DIDDocument issuer, String storepass)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(id, issuer, null, storepass, null);
	}

	public static void revoke(String id, DIDDocument issuer, String storepass,
			DIDTransactionDispatcher dispatcher)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(DIDURL.valueOf(id), issuer, null, storepass, dispatcher);
	}

	public static void revoke(String id, DIDDocument issuer, String storepass)
			throws CredentialInvalidException, DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDResolveException, DIDTransactionException {
		revoke(DIDURL.valueOf(id), issuer, null, storepass, null);
	}

	public static CompletableFuture<Void> revokeAsync(DIDURL id, DIDDocument issuer,
			DIDURL signKey, String storepass, DIDTransactionDispatcher dispatcher) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				revoke(id, issuer, signKey, storepass, dispatcher);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	public static CompletableFuture<Void> revokeAsync(DIDURL id,
			DIDDocument issuer, DIDURL signKey, String storepass) {
		return revokeAsync(id, issuer, signKey, storepass, null);
	}

	public static CompletableFuture<Void> revokeAsync(String id, DIDDocument issuer,
			String signKey, String storepass, DIDTransactionDispatcher dispatcher) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				revoke(id, issuer, signKey, storepass, dispatcher);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	public static CompletableFuture<Void> revokeAsync(String id,
			DIDDocument issuer, String signKey, String storepass) {
		return revokeAsync(id, issuer, signKey, storepass, null);
	}

	public static CompletableFuture<Void> revokeAsync(DIDURL id, DIDDocument issuer,
			String storepass, DIDTransactionDispatcher dispatcher) {
		return revokeAsync(id, issuer, null, storepass, dispatcher);
	}

	public static CompletableFuture<Void> revokeAsync(DIDURL id,
			DIDDocument issuer, String storepass) {
		return revokeAsync(id, issuer, null, storepass, null);
	}

	public static CompletableFuture<Void> revokeAsync(String id, DIDDocument issuer,
			String storepass, DIDTransactionDispatcher dispatcher) {
		return revokeAsync(id, issuer, null, storepass, dispatcher);
	}

	public static CompletableFuture<Void> revokeAsync(String id,
			DIDDocument issuer, String storepass) {
		return revokeAsync(id, issuer, null, storepass, null);
	}

	public static VerifiableCredential resolve(DIDURL id, DID issuer, boolean force)
			throws DIDResolveException {
		if (id == null)
			throw new IllegalArgumentException();

		VerifiableCredential vc = DIDBackend.getInstance().resolveCredential(
				id, issuer, force);
		if (vc != null)
			id.setMetadata(vc.getMetadata());

		return vc;
	}

	public static VerifiableCredential resolve(String id, String issuer, boolean force)
			throws DIDResolveException {
		return resolve(DIDURL.valueOf(id), DID.valueOf(issuer), force);
	}

	public static VerifiableCredential resolve(DIDURL id, DID issuer)
			throws DIDResolveException {
		return resolve(id, issuer, false);
	}

	public static VerifiableCredential resolve(String id, String issuer)
			throws DIDResolveException {
		return resolve(DIDURL.valueOf(id), DID.valueOf(issuer), false);
	}

	/**
	 * Resolve VerifiableCredential object.
	 *
	 * @param id the credential id
	 * @param force if true ignore local cache and try to resolve from ID chain
	 * @return the VerifiableCredential object
	 * @throws DIDResolveException throw this exception if resolving did failed.
	 */
	public static VerifiableCredential resolve(DIDURL id, boolean force)
			throws DIDResolveException {
		return resolve(id, null, force);
	}

	/**
	 * Resolve VerifiableCredential object.
	 *
	 * @param id the credential id
	 * @param force if true ignore local cache and try to resolve from ID chain
	 * @return the VerifiableCredential object
	 * @throws DIDResolveException throw this exception if resolving did failed
	 */
	public static VerifiableCredential resolve(String id, boolean force)
			throws DIDResolveException {
		return resolve(DIDURL.valueOf(id), null, force);
	}

	/**
	 * Resolve VerifiableCredential object.
	 *
	 * @param id the credential id
	 * @return the VerifiableCredential object
	 * @throws DIDResolveException throw this exception if resolving did failed.
	 */
	public static VerifiableCredential resolve(DIDURL id)
			throws DIDResolveException {
		return resolve(id, null, false);
	}

	/**
	 * Resolve VerifiableCredential object.
	 *
	 * @param id the credential id
	 * @return the VerifiableCredential object
	 * @throws DIDResolveException throw this exception if resolving did failed.
	 */
	public static VerifiableCredential resolve(String id)
			throws DIDResolveException {
		return resolve(DIDURL.valueOf(id), null, false);
	}

	/**
	 * Resolve VerifiableCredential object.
	 *
	 * @param id the credential id
	 * @param force if true ignore local cache and try to resolve from ID chain
	 * @return the new CompletableStage, the result is the DIDDocument interface for
	 *             resolved DIDDocument if success; null otherwise.
	 */
	public static CompletableFuture<VerifiableCredential> resolveAsync(DIDURL id, DID issuer, boolean force) {
		CompletableFuture<VerifiableCredential> future = CompletableFuture.supplyAsync(() -> {
			try {
				return resolve(id, issuer, force);
			} catch (DIDBackendException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Resolve VerifiableCredential object.
	 *
	 * @param id the credential id
	 * @param force if true ignore local cache and try to resolve from ID chain
	 * @return the new CompletableStage, the result is the DIDDocument interface for
	 *             resolved DIDDocument if success; null otherwise.
	 */
	public static CompletableFuture<VerifiableCredential> resolveAsync(String id, String issuer, boolean force) {
		CompletableFuture<VerifiableCredential> future = CompletableFuture.supplyAsync(() -> {
			try {
				return resolve(id, issuer, force);
			} catch (DIDBackendException | MalformedDIDURLException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	public static CompletableFuture<VerifiableCredential> resolveAsync(DIDURL id, DID issuer) {
		return resolveAsync(id, issuer, false);
	}

	public static CompletableFuture<VerifiableCredential> resolveAsync(String id, String issuer) {
		return resolveAsync(id, issuer, false);
	}

	public static CompletableFuture<VerifiableCredential> resolveAsync(DIDURL id, boolean force) {
		return resolveAsync(id, null, force);
	}

	public static CompletableFuture<VerifiableCredential> resolveAsync(String id, boolean force) {
		return resolveAsync(id, null, force);
	}

	/**
	 * Resolve VerifiableCredential object.
	 *
	 * @param id the credential id
	 * @return the new CompletableStage, the result is the DIDDocument interface for
	 *             resolved DIDDocument if success; null otherwise.
	 */
	public static CompletableFuture<VerifiableCredential> resolveAsync(DIDURL id) {
		return resolveAsync(id, null, false);
	}

	/**
	 * Resolve VerifiableCredential object.
	 *
	 * @param id the credential id
	 * @return the new CompletableStage, the result is the DIDDocument interface for
	 *             resolved DIDDocument if success; null otherwise.
	 */
	public static CompletableFuture<VerifiableCredential> resolveAsync(String id) {
		return resolveAsync(id, null, false);
	}

	public static CredentialBiography resolveBiography(DIDURL id, DID issuer)
			throws DIDResolveException {
		checkArgument(id != null, "Invalid credential id");

		return DIDBackend.getInstance().resolveCredentialBiography(id, issuer);
	}

	public static CredentialBiography resolveBiography(DIDURL id)
			throws DIDResolveException {
		checkArgument(id != null, "Invalid credential id");

		return DIDBackend.getInstance().resolveCredentialBiography(id);
	}

	public static CredentialBiography resolveBiography(String id, String issuer)
			throws DIDResolveException {
		return resolveBiography(DIDURL.valueOf(id), DID.valueOf(issuer));
	}

	public static CredentialBiography resolveBiography(String id)
			throws DIDResolveException {
		return resolveBiography(id, null);
	}

	public static CompletableFuture<CredentialBiography> resolveBiographyAsync(DIDURL id, DID issuer) {
		CompletableFuture<CredentialBiography> future = CompletableFuture.supplyAsync(() -> {
			try {
				return resolveBiography(id, issuer);
			} catch (DIDResolveException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	public static CompletableFuture<CredentialBiography> resolveBiographyAsync(DIDURL id) {
		CompletableFuture<CredentialBiography> future = CompletableFuture.supplyAsync(() -> {
			try {
				return resolveBiography(id);
			} catch (DIDResolveException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	public static CompletableFuture<CredentialBiography> resolveBiographyAsync(String id, String issuer) {
		CompletableFuture<CredentialBiography> future = CompletableFuture.supplyAsync(() -> {
			try {
				return resolveBiography(id, issuer);
			} catch (DIDResolveException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	public static CompletableFuture<CredentialBiography> resolveBiographyAsync(String id) {
		CompletableFuture<CredentialBiography> future = CompletableFuture.supplyAsync(() -> {
			try {
				return resolveBiography(id);
			} catch (DIDResolveException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	public static List<DIDURL> list(DID did, int skip, int limit)
			throws DIDResolveException {
		checkArgument(did != null, "Invalid did");

		return DIDBackend.getInstance().listCredentials(did, skip, limit);
	}

	public static List<DIDURL> list(DID did, int limit)
			throws DIDResolveException {
		checkArgument(did != null, "Invalid did");

		return DIDBackend.getInstance().listCredentials(did, 0, limit);
	}

	public static List<DIDURL> list(DID did)
			throws DIDResolveException {
		checkArgument(did != null, "Invalid did");

		return DIDBackend.getInstance().listCredentials(did, 0, 0);
	}

	public static CompletableFuture<List<DIDURL>> listAsync(DID did, int skip, int limit) {
		CompletableFuture<List<DIDURL>> future = CompletableFuture.supplyAsync(() -> {
			try {
				return list(did, skip, limit);
			} catch (DIDResolveException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	public static CompletableFuture<List<DIDURL>> listAsync(DID did, int limit) {
		return listAsync(did, 0, limit);
	}

	public static CompletableFuture<List<DIDURL>> listAsync(DID did) {
		return listAsync(did, 0, 0);
	}

	/**
	 * Parse a VerifiableCredential object from from a string JSON
	 * representation.
	 *
	 * @param content the string JSON content for building the object
	 * @return the VerifiableCredential object
	 * @throws DIDSyntaxException if a parse error occurs
	 */
	public static VerifiableCredential parse(String content)
			throws DIDSyntaxException {
		return parse(content, VerifiableCredential.class);
	}

	/**
	 * Parse a VerifiableCredential object from from a Reader object.
	 *
	 * @param src Reader object used to read JSON content for building the object
	 * @return the VerifiableCredential object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static VerifiableCredential parse(Reader src)
			throws DIDSyntaxException, IOException {
		return parse(src, VerifiableCredential.class);
	}

	/**
	 * Parse a VerifiableCredential object from from a InputStream object.
	 *
	 * @param src InputStream object used to read JSON content for building the object
	 * @return the VerifiableCredential object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static VerifiableCredential parse(InputStream src)
			throws DIDSyntaxException, IOException {
		return parse(src, VerifiableCredential.class);
	}

	/**
	 * Parse a VerifiableCredential object from from a File object.
	 *
	 * @param src File object used to read JSON content for building the object
	 * @return the VerifiableCredential object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static VerifiableCredential parse(File src)
			throws DIDSyntaxException, IOException {
		return parse(src, VerifiableCredential.class);
	}

	/**
	 * Parse a VerifiableCredential object from from a string JSON
	 * representation.
	 *
	 * @param content the string JSON content for building the object
	 * @return the VerifiableCredential object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @deprecated use {@link #parse(String)} instead
	 */
	@Deprecated
	public static VerifiableCredential fromJson(String content)
			throws DIDSyntaxException {
		return parse(content);
	}

	/**
	 * Parse a VerifiableCredential object from from a Reader object.
	 *
	 * @param src Reader object used to read JSON content for building the object
	 * @return the VerifiableCredential object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(Reader)} instead
	 */
	@Deprecated
	public static VerifiableCredential fromJson(Reader src)
			throws DIDSyntaxException, IOException {
		return parse(src);
	}

	/**
	 * Parse a VerifiableCredential object from from a InputStream object.
	 *
	 * @param src InputStream object used to read JSON content for building the object
	 * @return the VerifiableCredential object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(InputStream)} instead
	 */
	@Deprecated
	public static VerifiableCredential fromJson(InputStream src)
			throws DIDSyntaxException, IOException {
		return parse(src);
	}

	/**
	 * Parse a VerifiableCredential object from from a File object.
	 *
	 * @param src File object used to read JSON content for building the object
	 * @return the VerifiableCredential object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(File)} instead
	 */
	@Deprecated
	public static VerifiableCredential fromJson(File src)
			throws DIDSyntaxException, IOException {
		return parse(src);
	}

	/**
	 * The builder object defines the APIs to create the Credential.
	 *
	 * The credential object is sealed object. After set the contents for new
	 * credential, should call seal {@link Builder#seal(String)} method to
	 * create the final credential object.
	 */
	public static class Builder {
		private Issuer issuer;
		private DID target;
		private VerifiableCredential credential;

		/**
		 * Create a credential builder for DID.
		 *
		 * @param target the owner of Credential
		 */
		protected Builder(Issuer issuer, DID target) {
			this.issuer = issuer;
			this.target = target;

			credential = new VerifiableCredential();
			credential.issuer = issuer.getDid();
			credential.subject = new Subject(target);
		}

		/**
		 * Set Credential id.
		 *
		 * @param id the Credential id
		 * @return the Builder object
		 */
		public Builder id(DIDURL id) {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			if (id == null || !id.getDid().equals(target))
				throw new IllegalArgumentException();

			credential.id = id;
			return this;
		}

		/**
		 * Set Credential id.
		 *
		 * @param id the Credential id
		 * @return the Builder object
		 */
		public Builder id(String id) {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			return id(DIDURL.valueOf(target, id));
		}

		/**
		 * Set Credential types.
		 *
		 * @param types the set of types
		 * @return the Builder object
		 */
		public Builder type(String ... types) {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			if (types == null || types.length == 0)
				throw new IllegalArgumentException();

			credential.setType(types);
			return this;
		}

		private Calendar getMaxExpires() {
			Calendar cal = Calendar.getInstance(Constants.UTC);
			if (credential.getIssuanceDate() != null)
				cal.setTime(credential.getIssuanceDate());
			cal.add(Calendar.YEAR, Constants.MAX_VALID_YEARS);

			return cal;
		}

		private Builder defaultExpirationDate() {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			credential.expirationDate = getMaxExpires().getTime();

			return this;
		}

		/**
		 * Set expires time for Credential.
		 *
		 * @param expirationDate the expires time
		 * @return the Builder object
		 */
		public Builder expirationDate(Date expirationDate) {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			if (expirationDate == null)
				return this;

			Calendar cal = Calendar.getInstance(Constants.UTC);
			cal.setTime(expirationDate);

			Calendar maxExpires = getMaxExpires();
			if (cal.after(maxExpires))
				cal = maxExpires;

			credential.expirationDate = cal.getTime();

			return this;
		}

		/**
		 * Set Credential's subject.
		 *
		 * @param properties the subject content
		 * @return the Builder object
		 */
		public Builder properties(Map<String, Object> properties) {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			if (properties == null || properties.size() == 0)
				throw new IllegalArgumentException();

			credential.subject.properties.clear();
			credential.subject.properties.putAll(properties);
			credential.subject.properties.remove(ID);
			return this;
		}

		/**
		 * Set Credential's subject.
		 *
		 * @param json the subject subject with json format
		 * @return the Builder object
		 */
		public Builder properties(String json) {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			if (json == null || json.isEmpty())
				throw new IllegalArgumentException();

			ObjectMapper mapper = getObjectMapper();
			Map<String, Object> props;
			try {
				props = mapper.readValue(json, new TypeReference<Map<String, Object>>() {});
			} catch (IOException e) {
				throw new IllegalArgumentException(e);
			}

			return properties(props);
		}

		/**
		 * Set Credential's subject.
		 *
		 * @param name the property name
		 * @param value the property value
		 * @return the Builder object
		 */
		public Builder propertie(String name, Object value) {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			if (name == null || name.isEmpty() || name.equals(ID))
				throw new IllegalArgumentException();

			credential.subject.setProperty(name, value);
			return this;
		}

		/**
		 * Seal the credential object, attach the generated proof to the
		 * credential.
		 *
		 * @param storepass the password for DIDStore
		 * @return the Credential object
		 * @throws MalformedCredentialException if the Credential is malformed
		 * @throws DIDStoreException if an error occurs when access DID store
		 */
		public VerifiableCredential seal(String storepass)
				throws MalformedCredentialException, DIDStoreException {
			if (credential == null)
				throw new IllegalStateException("Credential already sealed.");

			if (storepass == null || storepass.isEmpty())
				throw new IllegalArgumentException();

			Calendar cal = Calendar.getInstance(Constants.UTC);
			credential.issuanceDate = cal.getTime();

			if (!credential.hasExpirationDate())
				defaultExpirationDate();

			credential.sanitize(false);

			String json;
			try {
				json = credential.serialize(true);
			} catch (DIDSyntaxException e) {
				// should never happen
				// re-throw it after up-cast
				throw (MalformedCredentialException)e;
			}

			String sig = issuer.sign(storepass, json.getBytes());

			Proof proof = new Proof(issuer.getSignKey(), sig);
			credential.proof = proof;

			// Invalidate builder
			VerifiableCredential vc = credential;
			this.credential = null;

			return vc;
		}
	}
}
