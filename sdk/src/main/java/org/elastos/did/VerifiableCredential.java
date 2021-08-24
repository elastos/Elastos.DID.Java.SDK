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

import org.elastos.did.backend.CredentialBiography;
import org.elastos.did.backend.CredentialTransaction;
import org.elastos.did.backend.IDChainRequest;
import org.elastos.did.exception.AlreadySealedException;
import org.elastos.did.exception.CredentialAlreadyExistException;
import org.elastos.did.exception.CredentialExpiredException;
import org.elastos.did.exception.CredentialNotGenuineException;
import org.elastos.did.exception.CredentialRevokedException;
import org.elastos.did.exception.DIDBackendException;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDNotFoundException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.MalformedCredentialException;
import org.elastos.did.exception.MalformedDIDURLException;
import org.elastos.did.exception.NotAttachedWithStoreException;
import org.elastos.did.exception.UnknownInternalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFilter;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ser.PropertyFilter;
import com.fasterxml.jackson.databind.ser.PropertyWriter;

/**
 * A verifiable credential can represent the information that a physical
 * credential represents. The addition of technologies, such as digital
 * signatures, makes verifiable credentials more tamper-evident and more
 * trustworthy than their physical counterparts.
 *
 * <p>
 * This class following W3C's
 * <a href="https://www.w3.org/TR/vc-data-model/">Verifiable Credentials Data Model 1.0</a>
 * specification.
 * </p>
 */
@JsonPropertyOrder({ VerifiableCredential.ID,
	VerifiableCredential.TYPE,
	VerifiableCredential.ISSUER,
	VerifiableCredential.ISSUANCE_DATE,
	VerifiableCredential.EXPIRATION_DATE,
	VerifiableCredential.CREDENTIAL_SUBJECT,
	VerifiableCredential.PROOF })
@JsonFilter("credentialFilter")
public class VerifiableCredential extends DIDEntity<VerifiableCredential> implements DIDObject {
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
	@JsonFormat(with = {JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY})
	private List<String> type;
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
	 * The credential Subject object contains one or more properties that are
	 * each related to a credential owner.
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
		 * Constructs the credential Subject object with given controller.
		 *
		 * @param id the controller of this subject
		 */
		@JsonCreator
		protected Subject(@JsonProperty(value = ID) DID id) {
			this.id = id;
			this.properties = new TreeMap<String, Object>();
		}

		/**
		 * Get the controller.
		 *
		 * @return the controller's DID object
		 */
		@JsonGetter(ID)
		public DID getId() {
			return id;
		}

		/**
		 * Set the controller of the Subject object.
		 *
		 * @param did the controller's DID
		 */
		void setId(DID did) {
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
				throw new UnknownInternalException(ignore);
			}
		}
	}

	/**
	 * The proof information for verifiable credential. The default proof
	 * type is ECDSAsecp256r1.
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
		 * Constructs a Proof object with the given values.
		 *
		 * @param type the verification method type
		 * @param method the verification method, normally it's a public key
		 * @param created the create date time stamp
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

		/**
		 * Constructs a Proof object with the given values.
		 *
		 * @param method the verification method, normally it's a public key
		 * @param signature the signature encoded in base64 URL safe format
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
		 * @return a verification method id
		 */
		public DIDURL getVerificationMethod() {
			return verificationMethod;
		}

		/**
		 * Get the created time stamp.
		 *
		 * @return the created time stamp
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

		static PropertyFilter getFilter() {
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
	 * Copy constructor.
	 *
	 * @param vc the source credential object
	 */
	private VerifiableCredential(VerifiableCredential vc, boolean withProof) {
		this.id = vc.id;
		this.type = vc.type;
		this.issuer = vc.issuer;
		this.issuanceDate = vc.issuanceDate;
		this.expirationDate = vc.expirationDate;
		this.subject = vc.subject;
		if (withProof)
			this.proof = vc.proof;
	}

	private void checkAttachedStore() throws NotAttachedWithStoreException {
		if (!getMetadata().attachedStore())
			throw new NotAttachedWithStoreException();
	}

	/**
	 * Get the id of this credential object
	 *
	 * @return the id of this credential
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
	public List<String> getType() {
		return Collections.unmodifiableList(type);
	}

	/**
	 * Get the issuer of this credential.
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
	 * Get the expire time.
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
	 * @return the last modified time, maybe null for old version credential object
	 */
	public Date getLastModified() {
		return proof.getCreated();
	}

	/**
	 * Get Credential subject object.
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
	 * @throws MalformedCredentialException if the credential object is invalid
	 */
	@Override
	protected void sanitize() throws MalformedCredentialException {
		if (id == null)
			throw new MalformedCredentialException("Missing credential id");

		if (type == null || type.isEmpty())
			throw new MalformedCredentialException("Missing credential type");

		if (issuanceDate == null)
			throw new MalformedCredentialException("Missing credential issuance date");

		if (subject == null)
			throw new MalformedCredentialException("Missing credential subject");

		if (subject.id == null)
			throw new MalformedCredentialException("Missing credential subject id");

		if (proof == null)
			throw new MalformedCredentialException("Missing credential proof");

		Collections.sort(type);

		// Update id references
		if (issuer == null)
			issuer = subject.id;

		if (id.getDid() == null)
			id.setDid(subject.id);

		if (proof.verificationMethod.getDid() == null)
			proof.verificationMethod.setDid(issuer);
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

	static PropertyFilter getFilter() {
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
	 * Set meta data for this credential object.
	 *
	 * @param metadata the metadata object
	 */
	protected void setMetadata(CredentialMetadata metadata) {
		this.metadata = metadata;
		this.getId().setMetadata(metadata);
	}

	/**
	 * Get the metadata object of this credential object.
	 *
	 * @return the Credential Meta data object
	 */
	public synchronized CredentialMetadata getMetadata() {
		if (metadata == null) {
			/*
			// This will cause resolve recursively
			try {
				VerifiableCredential resolved = VerifiableCredential.resolve(getId(), getIssuer());
				metadata = resolved != null ? resolved.getMetadata() : new CredentialMetadata(getId());
			} catch (DIDResolveException e) {
				metadata = new CredentialMetadata(getId());
			}
			*/
			metadata = new CredentialMetadata(getId());
		}

		return metadata;
	}

	/**
	 * Whether the credential object has metadata attached.
	 *
	 * @return true if has metadata attached, false otherwise
	 */
	protected boolean hasMetadata() {
		if (metadata == null)
			return false;

		if (metadata.isEmpty())
			return false;

		return true;
	}

	/**
	 * Get the attached DIDStore object.
	 *
	 * @return the DIDStore object if attached with store, null otherwise
	 */
	private DIDStore getStore() {
		return metadata.getStore();
	}

	/**
	 * Check if this credential is a self proclaimed or not.
	 *
	 * @return whether the credential is self proclaimed
	 */
	public boolean isSelfProclaimed() {
		return issuer.equals(subject.id);
	}

	/**
	 * Check if this credential object is expired or not.
	 *
	 * @return whether the credential object is expired
	 * @throws DIDResolveException if error occurs when resolving the DIDs
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
		if (controllerDoc != null && controllerDoc.isExpired())
			return true;

		if (!isSelfProclaimed()) {
			DIDDocument issuerDoc = issuer.resolve();
			if (issuerDoc != null && issuerDoc.isExpired())
				return true;
		}

		return false;
	}

	/**
	 * Check if this credential object is expired or not in asynchronous mode.
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
	 * Check whether this credential object is genuine or not.
	 *
	 * @param listener the listener for the verification events and messages
	 * @return whether the credential object is genuine
	 * @throws DIDResolveException if error occurs when resolve the DIDs
	 */
	public boolean isGenuine(VerificationEventListener listener) throws DIDResolveException {
		if (!getId().getDid().equals(getSubject().getId())) {
			if (listener != null) {
				listener.failed(this, "VC %s: invalid id '%s', should under the scope of '%s'",
						getId(), getId(), getSubject().getId());
				listener.failed(this, "VC %s: is not genuine", getId());
			}

			return false;
		}

		DIDDocument issuerDoc = issuer.resolve();
		if (issuerDoc == null) {
			//throw new DIDNotFoundException(issuer.toString());
			if (listener != null) {
				listener.failed(this, "VC %s: Can not resolve the document for issuer '%s'",
						getId(), getIssuer());
				listener.failed(this, "VC %s: is not genuine", getId());
			}

			return false;
		}

		if (!issuerDoc.isGenuine(listener)) {
			if (listener != null) {
				listener.failed(this, "VC %s: issuer '%s' is not genuine",
						getId(), getIssuer());
				listener.failed(this, "VC %s: is not genuine", getId());
			}

			return false;
		}


		// Credential should signed by any authentication key.
		if (!issuerDoc.isAuthenticationKey(proof.getVerificationMethod())) {
			if (listener != null) {
				listener.failed(this, "VC %s: key '%s' for proof is not an authencation key of '%s'",
						getId(), proof.getVerificationMethod(), proof.getVerificationMethod().getDid());
				listener.failed(this, "VC %s: is not genuine", getId());
			}

			return false;
		}

		// Unsupported public key type;
		if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE)) {
			if (listener != null) {
				listener.failed(this, "VC %s: key type '%s' for proof is not supported",
						getId(), proof.getType());
				listener.failed(this, "VC %s: is not genuine", getId());
			}

			return false;
		}

		VerifiableCredential vc = new VerifiableCredential(this, false);
		String json = vc.serialize(true);
		if (!issuerDoc.verify(proof.getVerificationMethod(),
				proof.getSignature(), json.getBytes())) {
			if (listener != null) {
				listener.failed(this, "VC %s: proof is invalid, signature mismatch", getId());
				listener.failed(this, "VC %s: is not genuine", getId());
			}

			return false;
		}

		if (!isSelfProclaimed()) {
			DIDDocument controllerDoc = subject.id.resolve();
			if (controllerDoc != null && !controllerDoc.isGenuine(listener)) {
				if (listener != null) {
					listener.failed(this, "VC %s: holder's document is not genuine", getId());
					listener.failed(this, "VC %s: is not genuine", getId());
				}

				return false;
			}
		}

		if (listener != null)
			listener.succeeded(this, "VC %s: is genuine", getId());

		return true;
	}

	/**
	 * Check whether this credential object is genuine or not.
	 *
	 * @return whether the credential object is genuine
	 * @throws DIDResolveException if error occurs when resolve the DIDs
	 */
	public boolean isGenuine() throws DIDResolveException {
		return isGenuine(null);
	}

	/**
	 * Check whether this credential object is genuine or not in asynchronous mode.
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
	 * Check whether this credential object is genuine or not in asynchronous mode.
	 *
	 * @return the new CompletableStage if success; null otherwise.
	 *         The boolean result is genuine or not
	 */
	public CompletableFuture<Boolean> isGenuineAsync() {
		return isGenuineAsync(null);
	}

	/**
	 * Check whether this credential object is revoked or not.
	 *
	 * @return whether the credential object is revoked
	 * @throws DIDResolveException if error occurs when resolve the DIDs
	 */
	public boolean isRevoked() throws DIDResolveException {
		if (getMetadata().isRevoked())
			return true;

		CredentialBiography bio = DIDBackend.getInstance().resolveCredentialBiography(
				getId(), getIssuer());
		boolean revoked = bio.getStatus() == CredentialBiography.Status.REVOKED;

		if (revoked)
			getMetadata().setRevoked(revoked);

		return revoked;
	}

	/**
	 * Check whether this credential object is revoked or not in asynchronous mode.
	 *
	 * @return the new CompletableStage if success; null otherwise.
	 *         The boolean result is revoked or not
	 */
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
	 * Check whether this credential object is valid or not.
	 *
	 * @param listener the listener for the verification events and messages
	 * @return whether the credential object is valid
	 * @throws DIDResolveException if error occurs when resolve the DIDs
	 */
	public boolean isValid(VerificationEventListener listener) throws DIDResolveException {
		if (expirationDate != null) {
			Calendar now = Calendar.getInstance(Constants.UTC);

			Calendar expireDate  = Calendar.getInstance(Constants.UTC);
			expireDate.setTime(expirationDate);

			if (now.after(expireDate)) {
				if (listener != null) {
					listener.failed(this, "VC %s: is expired", getId());
					listener.failed(this, "VC %s: is invalid", getId());
				}

				return false;
			}
		}

		DIDDocument issuerDoc = issuer.resolve();
		if (issuerDoc == null) {
			//throw new DIDNotFoundException(issuer.toString());
			if (listener != null) {
				listener.failed(this, "VC %s: can not resolve the document for issuer '%s'",
						getId(), getIssuer());
				listener.failed(this, "VC %s: is invalid", getId());
			}

			return false;
		}

		if (!issuerDoc.isValid(listener)) {
			if (listener != null) {
				listener.failed(this, "VC %s: issuer '%s' is invalid",
						getId(), getIssuer());
				listener.failed(this, "VC %s: is invalid", getId());
			}

			return false;
		}

		// Credential should signed by any authentication key.
		if (!issuerDoc.isAuthenticationKey(proof.getVerificationMethod())) {
			if (listener != null) {
				listener.failed(this, "VC %s: key '%s' for proof is not an authencation key of '%s'",
						getId(), proof.getVerificationMethod(), proof.getVerificationMethod().getDid());
				listener.failed(this, "VC %s: is invalid", this.getSubject());
			}

			return false;
		}

		// Unsupported public key type;
		if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE)){
			if (listener != null) {
				listener.failed(this, "VC %s: key type '%s' for proof is not supported",
						getId(), proof.getType());
				listener.failed(this, "VC %s: is invalid", getId());
			}

			return false;
		}

		VerifiableCredential vc = new VerifiableCredential(this, false);
		String json = vc.serialize(true);
		if (!issuerDoc.verify(proof.getVerificationMethod(),
				proof.getSignature(), json.getBytes())){
			if (listener != null) {
				listener.failed(this, "VC %s: proof is invalid, signature mismatch", getId());
				listener.failed(this, "VC %s: is invalid", getId());
			}

			return false;
		}

		if (!isSelfProclaimed()) {
			DIDDocument controllerDoc = subject.id.resolve();
			if (controllerDoc != null && !controllerDoc.isValid(listener)) {
				if (listener != null) {
					listener.failed(this, "VC %s: holder's document is invalid", getId());
					listener.failed(this, "VC %s: is invalid", getId());
				}

				return false;
			}
		}

		if (listener != null)
			listener.succeeded(this, "VC %s: is valid", getId());

		return true;
	}

	/**
	 * Check whether this credential object is valid or not.
	 *
	 * @return whether the credential object is valid
	 * @throws DIDResolveException if error occurs when resolve the DIDs
	 */
	public boolean isValid() throws DIDResolveException {
		return isValid(null);
	}

	/**
	 * Check whether this credential object is valid in asynchronous mode.
	 *
	 * @param listener the listener for the verification events and messages
	 * @return the new CompletableStage if success; null otherwise.
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
	 * Check whether this credential object is valid in asynchronous mode.
	 *
	 * @return the new CompletableStage if success; null otherwise.
	 * 	       The boolean result is valid or not
	 */
	public CompletableFuture<Boolean> isValidAsync() {
		return isValidAsync(null);
	}

	/**
	 * Check whether this credential object was declared or not.
	 *
	 * @return whether the credential object was declared
	 * @throws DIDResolveException if error occurs when resolve the DIDs
	 */
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

	/**
	 * Check whether this credential object was declared in asynchronous mode.
	 *
	 * @return the new CompletableStage if success; null otherwise.
	 * 	       The boolean result was declared or not
	 */
	public CompletableFuture<Boolean> wasDeclaredAsync() {
		CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
			try {
				return wasDeclared();
			} catch (DIDResolveException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Publish this credential object to the ID chain, declare it to the public.
	 *
	 * <p>
	 * Only the owner of the credential object who can declare credential to
	 * public.
	 * </p>
	 *
	 * @param signKey the contoller's key id to sign the declare transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void declare(DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkAttachedStore();

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

		if (signKey == null && owner.getDefaultPublicKeyId() == null)
			throw new InvalidKeyException("Unknown sign key");

		if (signKey != null) {
			if (!owner.isAuthenticationKey(signKey))
				throw new InvalidKeyException(signKey.toString());
		} else {
			signKey = owner.getDefaultPublicKeyId();
		}

		DIDBackend.getInstance().declareCredential(this, owner, signKey, storepass, adapter);
	}

	/**
	 * Publish this credential object to the ID chain, declare it to the public.
	 *
	 * <p>
	 * Only the owner of the credential object who can declare credential to
	 * public.
	 * </p>
	 *
	 * @param signKey the contoller's key id to sign the declare transaction
	 * @param storepass the password of the DID store
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void declare(DIDURL signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		declare(signKey, storepass, null);
	}

	/**
	 * Publish this credential object to the ID chain, declare it to the public.
	 *
	 * <p>
	 * Only the owner of the credential object who can declare credential to
	 * public.
	 * </p>
	 *
	 * @param signKey the contoller's key id to sign the declare transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void declare(String signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		declare(DIDURL.valueOf(getSubject().getId(), signKey), storepass, adapter);
	}

	/**
	 * Publish this credential object to the ID chain, declare it to the public.
	 *
	 * <p>
	 * Only the owner of the credential object who can declare credential to
	 * public.
	 * </p>
	 *
	 * @param signKey the contoller's key id to sign the declare transaction
	 * @param storepass the password of the DID store
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void declare(String signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		declare(DIDURL.valueOf(getSubject().getId(), signKey), storepass, null);
	}

	/**
	 * Publish this credential object to the ID chain, declare it to the public.
	 *
	 * <p>
	 * Only the owner of the credential object who can declare credential to
	 * public.
	 * </p>
	 *
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void declare(String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		declare((DIDURL)null, storepass, adapter);
	}

	/**
	 * Publish this credential object to the ID chain, declare it to the public.
	 *
	 * <p>
	 * Only the owner of the credential object who can declare credential to
	 * public.
	 * </p>
	 *
	 * @param storepass the password of the DID store
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void declare(String storepass)
			throws DIDStoreException, DIDBackendException {
		declare((DIDURL)null, storepass, null);
	}

	/**
	 * Publish this credential object to the ID chain, declare it to the public
	 * in asynchronous mode.
	 *
	 * <p>
	 * Only the owner of the credential object who can declare credential to
	 * public.
	 * </p>
	 *
	 * @param signKey the contoller's key id to sign the declare transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> declareAsync(DIDURL signKey, String storepass,
			DIDTransactionAdapter adapter) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				declare(signKey, storepass, adapter);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Publish this credential object to the ID chain, declare it to the public
	 * in asynchronous mode.
	 *
	 * <p>
	 * Only the owner of the credential object who can declare credential to
	 * public.
	 * </p>
	 *
	 * @param signKey the contoller's key id to sign the declare transaction
	 * @param storepass the password of the DID store
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> declareAsync(DIDURL signKey, String storepass) {
		return declareAsync(signKey, storepass, null);
	}

	/**
	 * Publish this credential object to the ID chain, declare it to the public
	 * in asynchronous mode.
	 *
	 * <p>
	 * Only the owner of the credential object who can declare credential to
	 * public.
	 * </p>
	 *
	 * @param signKey the contoller's key id to sign the declare transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> declareAsync(String signKey, String storepass,
			DIDTransactionAdapter adapter) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				declare(signKey, storepass, adapter);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Publish this credential object to the ID chain, declare it to the public
	 * in asynchronous mode.
	 *
	 * <p>
	 * Only the owner of the credential object who can declare credential to
	 * public.
	 * </p>
	 *
	 * @param signKey the contoller's key id to sign the declare transaction
	 * @param storepass the password of the DID store
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> declareAsync(String signKey, String storepass) {
		return declareAsync(signKey, storepass, null);
	}

	/**
	 * Publish this credential object to the ID chain, declare it to the public
	 * in asynchronous mode.
	 *
	 * <p>
	 * Only the owner of the credential object who can declare credential to
	 * public.
	 * </p>
	 *
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> declareAsync(String storepass,
			DIDTransactionAdapter adapter) {
		return declareAsync((DIDURL)null, storepass, adapter);
	}

	/**
	 * Publish this credential object to the ID chain, declare it to the public
	 * in asynchronous mode.
	 *
	 * <p>
	 * Only the owner of the credential object who can declare credential to
	 * public.
	 * </p>
	 *
	 * @param storepass the password of the DID store
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> declareAsync(String storepass) {
		return declareAsync((DIDURL)null, storepass, null);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void revoke(DIDDocument signer, DIDURL signKey, String storepass,
			DIDTransactionAdapter adapter) throws DIDStoreException, DIDBackendException {
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkAttachedStore();

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

		if (signKey == null && signer.getDefaultPublicKeyId() == null)
			throw new InvalidKeyException("Unknown sign key");

		if (signKey != null) {
			if (!signer.isAuthenticationKey(signKey))
				throw new InvalidKeyException(signKey.toString());
		} else {
			signKey = signer.getDefaultPublicKeyId();
		}

		DIDBackend.getInstance().revokeCredential(this, signer, signKey, storepass, adapter);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void revoke(DIDDocument signer, DIDURL signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		revoke(signer, signKey, storepass, null);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void revoke(DIDDocument signer, String signKey, String storepass,
			DIDTransactionAdapter adapter) throws DIDStoreException, DIDBackendException {
		revoke(signer, DIDURL.valueOf(getSubject().getId(), signKey), storepass, adapter);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void revoke(DIDDocument signer, String signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		revoke(signer, signKey, storepass, null);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signer the DID document of credential owner or issuer
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void revoke(DIDDocument signer, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		revoke(signer, (DIDURL)null, storepass, adapter);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signer the DID document of credential owner or issuer
	 * @param storepass the password of the DID store
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void revoke(DIDDocument signer, String storepass)
			throws DIDStoreException, DIDBackendException {
		revoke(signer, (DIDURL)null, storepass, null);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void revoke(DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		revoke(null, signKey, storepass, adapter);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void revoke(DIDURL signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		revoke(null, signKey, storepass, null);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void revoke(String signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		revoke(null, signKey, storepass, adapter);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void revoke(String signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		revoke(null, signKey, storepass, null);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void revoke(String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		revoke(null, (DIDURL)null, storepass, adapter);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param storepass the password of the DID store
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public void revoke(String storepass) throws DIDStoreException, DIDBackendException {
		revoke(null, (DIDURL)null, storepass, null);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain in asynchronous mode.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> revokeAsync(DIDDocument signer,
			DIDURL signKey, String storepass, DIDTransactionAdapter adapter) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				revoke(signer, signKey, storepass, adapter);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain in asynchronous mode.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> revokeAsync(DIDDocument signer,
			DIDURL signKey, String storepass) {
		return revokeAsync(signer, signKey, storepass, null);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain in asynchronous mode.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> revokeAsync(DIDDocument signer,
			String signKey, String storepass, DIDTransactionAdapter adapter) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				revoke(signer, signKey, storepass, adapter);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain in asynchronous mode.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> revokeAsync(DIDDocument signer,
			String signKey, String storepass) {
		return revokeAsync(signer, signKey, storepass, null);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain in asynchronous mode.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signer the DID document of credential owner or issuer
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> revokeAsync(DIDDocument signer,
			String storepass, DIDTransactionAdapter adapter) {
		return revokeAsync(signer, (DIDURL)null, storepass, null);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain in asynchronous mode.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signer the DID document of credential owner or issuer
	 * @param storepass the password of the DID store
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> revokeAsync(DIDDocument signer,
			String storepass) {
		return revokeAsync(signer, (DIDURL)null, storepass, null);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain in asynchronous mode.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> revokeAsync(DIDURL signKey, String storepass,
			DIDTransactionAdapter adapter) {
		return revokeAsync(null, signKey, storepass, null);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain in asynchronous mode.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> revokeAsync(DIDURL signKey, String storepass) {
		return revokeAsync(null, signKey, storepass, null);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain in asynchronous mode.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> revokeAsync(String signKey, String storepass,
			DIDTransactionAdapter adapter) {
		return revokeAsync(null, signKey, storepass, null);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain in asynchronous mode.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> revokeAsync(String signKey, String storepass) {
		return revokeAsync(null, signKey, storepass, null);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain in asynchronous mode.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> revokeAsync(String storepass,
			DIDTransactionAdapter adapter) {
		return revokeAsync(null, (DIDURL)null, storepass, adapter);
	}

	/**
	 * Revoke this credential object and announce the revocation to the ID
	 * chain in asynchronous mode.
	 *
	 * <p>
	 * The credential owner and issuer both can revoke the credential.
	 * </p>
	 *
	 * @param storepass the password of the DID store
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> revokeAsync(String storepass) {
		return revokeAsync(null, (DIDURL)null, storepass, null);
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public static void revoke(DIDURL id, DIDDocument signer, DIDURL signKey,
			String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		checkArgument(id != null, "Invalid credential id");
		checkArgument(signer != null, "Invalid issuer's document");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		if (!signer.getMetadata().attachedStore())
			throw new NotAttachedWithStoreException(signer.getSubject().toString());

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

		if (signKey == null && signer.getDefaultPublicKeyId() == null)
			throw new InvalidKeyException("Unknown sign key");

		if (signKey != null) {
			if (!signer.isAuthenticationKey(signKey))
				throw new InvalidKeyException(signKey.toString());
		} else {
			signKey = signer.getDefaultPublicKeyId();
		}

		DIDBackend.getInstance().revokeCredential(id, signer, signKey, storepass, adapter);
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public static void revoke(DIDURL id, DIDDocument signer, DIDURL signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		revoke(id, signer, signKey, storepass, null);
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public static void revoke(String id, DIDDocument signer, String signKey,
			String storepass, DIDTransactionAdapter adapter)
					throws DIDStoreException, DIDBackendException {
		revoke(DIDURL.valueOf(id), signer, DIDURL.valueOf(signer.getSubject(), signKey),
				storepass, adapter);
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public static void revoke(String id, DIDDocument signer, String signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		revoke(DIDURL.valueOf(id), signer, DIDURL.valueOf(signer.getSubject(), signKey),
				storepass, null);
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public static void revoke(DIDURL id, DIDDocument signer, String storepass,
			DIDTransactionAdapter adapter) throws DIDStoreException, DIDBackendException {
		revoke(id, signer, null, storepass, adapter);
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param storepass the password of the DID store
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public static void revoke(DIDURL id, DIDDocument signer, String storepass)
			throws DIDStoreException, DIDBackendException {
		revoke(id, signer, null, storepass, null);
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public static void revoke(String id, DIDDocument signer, String storepass,
			DIDTransactionAdapter adapter) throws DIDStoreException, DIDBackendException {
		revoke(DIDURL.valueOf(id), signer, null, storepass, adapter);
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param storepass the password of the DID store
	 * @throws DIDStoreException if an error occurred when accessing the DID store
	 * @throws DIDBackendException if an error occurred when publish the transaction
	 */
	public static void revoke(String id, DIDDocument signer, String storepass)
			throws DIDStoreException, DIDBackendException {
		revoke(DIDURL.valueOf(id), signer, null, storepass, null);
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain
	 * in asynchronous mode.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @return the new CompletableStage
	 */
	public static CompletableFuture<Void> revokeAsync(DIDURL id, DIDDocument signer,
			DIDURL signKey, String storepass, DIDTransactionAdapter adapter) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				revoke(id, signer, signKey, storepass, adapter);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain
	 * in asynchronous mode.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @return the new CompletableStage
	 */
	public static CompletableFuture<Void> revokeAsync(DIDURL id,
			DIDDocument signer, DIDURL signKey, String storepass) {
		return revokeAsync(id, signer, signKey, storepass, null);
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain
	 * in asynchronous mode.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @return the new CompletableStage
	 */
	public static CompletableFuture<Void> revokeAsync(String id, DIDDocument signer,
			String signKey, String storepass, DIDTransactionAdapter adapter) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				revoke(id, signer, signKey, storepass, adapter);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain
	 * in asynchronous mode.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param signKey the key id to sign the revoke transaction
	 * @param storepass the password of the DID store
	 * @return the new CompletableStage
	 */
	public static CompletableFuture<Void> revokeAsync(String id,
			DIDDocument signer, String signKey, String storepass) {
		return revokeAsync(id, signer, signKey, storepass, null);
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain
	 * in asynchronous mode.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @return the new CompletableStage
	 */
	public static CompletableFuture<Void> revokeAsync(DIDURL id, DIDDocument signer,
			String storepass, DIDTransactionAdapter adapter) {
		return revokeAsync(id, signer, null, storepass, adapter);
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain
	 * in asynchronous mode.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param storepass the password of the DID store
	 * @return the new CompletableStage
	 */
	public static CompletableFuture<Void> revokeAsync(DIDURL id,
			DIDDocument signer, String storepass) {
		return revokeAsync(id, signer, null, storepass, null);
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain
	 * in asynchronous mode.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param storepass the password of the DID store
	 * @param adapter an optional DIDTransactionAdapter object, use the
	 * 				  DIDBackend's default implementation if null
	 * @return the new CompletableStage
	 */
	public static CompletableFuture<Void> revokeAsync(String id, DIDDocument signer,
			String storepass, DIDTransactionAdapter adapter) {
		return revokeAsync(id, signer, null, storepass, adapter);
	}

	/**
	 * Revoke a credential by id and announce the revocation to the ID chain
	 * in asynchronous mode.
	 *
	 * @param id the id of the credential to be revoke
	 * @param signer the DID document of credential owner or issuer
	 * @param storepass the password of the DID store
	 * @return the new CompletableStage
	 */
	public static CompletableFuture<Void> revokeAsync(String id,
			DIDDocument signer, String storepass) {
		return revokeAsync(id, signer, null, storepass, null);
	}

	/**
	 * Resolve the specific VerifiableCredential object.
	 *
	 * @param id the id of the target credential
	 * @param issuer optional, the issuer's did
	 * @param force if true then ignore the local cache and resolve the
	 * 				credential from the ID chain directly; otherwise will try
	 * 				to load the credential from the local cache, if the local
	 * 				cache not contains this credential, then resolve it from
	 * 				the ID chain
	 * @return the resolved VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
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

	/**
	 * Resolve the specific VerifiableCredential object.
	 *
	 * @param id the id of the target credential
	 * @param issuer optional, the issuer's did
	 * @param force if true then ignore the local cache and resolve the
	 * 				credential from the ID chain directly; otherwise will try
	 * 				to load the credential from the local cache, if the local
	 * 				cache not contains this credential, then resolve it from
	 * 				the ID chain
	 * @return the resolved VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
	public static VerifiableCredential resolve(String id, String issuer, boolean force)
			throws DIDResolveException {
		return resolve(DIDURL.valueOf(id), DID.valueOf(issuer), force);
	}

	/**
	 * Resolve the specific VerifiableCredential object.
	 *
	 * <p>
	 * By default, this method will try to load the credential from the local
	 * cache, if the local cache not contains this credential, then try
	 * to resolve it from the ID chain.
	 * </p>
	 *
	 * @param id the id of the target credential
	 * @param issuer optional, the issuer's did
	 * @return the resolved VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
	public static VerifiableCredential resolve(DIDURL id, DID issuer)
			throws DIDResolveException {
		return resolve(id, issuer, false);
	}

	/**
	 * Resolve the specific VerifiableCredential object.
	 *
	 * <p>
	 * By default, this method will try to load the credential from the local
	 * cache, if the local cache not contains this credential, then try
	 * to resolve it from the ID chain.
	 * </p>
	 *
	 * @param id the id of the target credential
	 * @param issuer optional, the issuer's did
	 * @return the resolved VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
	public static VerifiableCredential resolve(String id, String issuer)
			throws DIDResolveException {
		return resolve(DIDURL.valueOf(id), DID.valueOf(issuer), false);
	}

	/**
	 * Resolve the specific VerifiableCredential object.
	 *
	 * @param id the id of the target credential
	 * @param force if true then ignore the local cache and resolve the
	 * 				credential from the ID chain directly; otherwise will try
	 * 				to load the credential from the local cache, if the local
	 * 				cache not contains this credential, then resolve it from
	 * 				the ID chain
	 * @return the resolved VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
	public static VerifiableCredential resolve(DIDURL id, boolean force)
			throws DIDResolveException {
		return resolve(id, null, force);
	}

	/**
	 * Resolve the specific VerifiableCredential object.
	 *
	 * @param id the id of the target credential
	 * @param force if true then ignore the local cache and resolve the
	 * 				credential from the ID chain directly; otherwise will try
	 * 				to load the credential from the local cache, if the local
	 * 				cache not contains this credential, then resolve it from
	 * 				the ID chain
	 * @return the resolved VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
	public static VerifiableCredential resolve(String id, boolean force)
			throws DIDResolveException {
		return resolve(DIDURL.valueOf(id), null, force);
	}

	/**
	 * Resolve the specific VerifiableCredential object.
	 *
	 * <p>
	 * By default, this method will try to load the credential from the local
	 * cache, if the local cache not contains this credential, then try
	 * to resolve it from the ID chain.
	 * </p>
	 *
	 * @param id the id of the target credential
	 * @return the resolved VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
	public static VerifiableCredential resolve(DIDURL id)
			throws DIDResolveException {
		return resolve(id, null, false);
	}

	/**
	 * Resolve the specific VerifiableCredential object.
	 *
	 * <p>
	 * By default, this method will try to load the credential from the local
	 * cache, if the local cache not contains this credential, then try
	 * to resolve it from the ID chain.
	 * </p>
	 *
	 * @param id the id of the target credential
	 * @return the resolved VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
	public static VerifiableCredential resolve(String id)
			throws DIDResolveException {
		return resolve(DIDURL.valueOf(id), null, false);
	}

	/**
	 * Resolve the specific VerifiableCredential object in asynchronous mode.
	 *
	 * @param id the id of the target credential
	 * @param issuer optional, the issuer's did
	 * @param force if true then ignore the local cache and resolve the
	 * 				credential from the ID chain directly; otherwise will try
	 * 				to load the credential from the local cache, if the local
	 * 				cache not contains this credential, then resolve it from
	 * 				the ID chain
	 * @return a new CompletableStage, the result is the resolved
	 * 			VerifiableCredential object if success; null otherwise
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
	 * Resolve the specific VerifiableCredential object in asynchronous mode.
	 *
	 * @param id the id of the target credential
	 * @param issuer optional, the issuer's did
	 * @param force if true then ignore the local cache and resolve the
	 * 				credential from the ID chain directly; otherwise will try
	 * 				to load the credential from the local cache, if the local
	 * 				cache not contains this credential, then resolve it from
	 * 				the ID chain
	 * @return a new CompletableStage, the result is the resolved
	 * 			VerifiableCredential object if success; null otherwise
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

	/**
	 * Resolve the specific VerifiableCredential object in asynchronous mode.
	 *
	 * <p>
	 * By default, this method will try to load the credential from the local
	 * cache, if the local cache not contains this credential, then try
	 * to resolve it from the ID chain.
	 * </p>
	 *
	 * @param id the id of the target credential
	 * @param issuer optional, the issuer's did
	 * @return a new CompletableStage, the result is the resolved
	 * 			VerifiableCredential object if success; null otherwise
	 */
	public static CompletableFuture<VerifiableCredential> resolveAsync(DIDURL id, DID issuer) {
		return resolveAsync(id, issuer, false);
	}

	/**
	 * Resolve the specific VerifiableCredential object in asynchronous mode.
	 *
	 * <p>
	 * By default, this method will try to load the credential from the local
	 * cache, if the local cache not contains this credential, then try
	 * to resolve it from the ID chain.
	 * </p>
	 *
	 * @param id the id of the target credential
	 * @param issuer optional, the issuer's did
	 * @return a new CompletableStage, the result is the resolved
	 * 			VerifiableCredential object if success; null otherwise
	 */
	public static CompletableFuture<VerifiableCredential> resolveAsync(String id, String issuer) {
		return resolveAsync(id, issuer, false);
	}

	/**
	 * Resolve the specific VerifiableCredential object in asynchronous mode.
	 *
	 * @param id the id of the target credential
	 * @param force if true then ignore the local cache and resolve the
	 * 				credential from the ID chain directly; otherwise will try
	 * 				to load the credential from the local cache, if the local
	 * 				cache not contains this credential, then resolve it from
	 * 				the ID chain
	 * @return a new CompletableStage, the result is the resolved
	 * 			VerifiableCredential object if success; null otherwise
	 */
	public static CompletableFuture<VerifiableCredential> resolveAsync(DIDURL id, boolean force) {
		return resolveAsync(id, null, force);
	}

	/**
	 * Resolve the specific VerifiableCredential object in asynchronous mode.
	 *
	 * @param id the id of the target credential
	 * @param force if true then ignore the local cache and resolve the
	 * 				credential from the ID chain directly; otherwise will try
	 * 				to load the credential from the local cache, if the local
	 * 				cache not contains this credential, then resolve it from
	 * 				the ID chain
	 * @return a new CompletableStage, the result is the resolved
	 * 			VerifiableCredential object if success; null otherwise
	 */
	public static CompletableFuture<VerifiableCredential> resolveAsync(String id, boolean force) {
		return resolveAsync(id, null, force);
	}

	/**
	 * Resolve the specific VerifiableCredential object in asynchronous mode.
	 *
	 * <p>
	 * By default, this method will try to load the credential from the local
	 * cache, if the local cache not contains this credential, then try
	 * to resolve it from the ID chain.
	 * </p>
	 *
	 * @param id the id of the target credential
	 * @return a new CompletableStage, the result is the resolved
	 * 			VerifiableCredential object if success; null otherwise
	 */
	public static CompletableFuture<VerifiableCredential> resolveAsync(DIDURL id) {
		return resolveAsync(id, null, false);
	}

	/**
	 * Resolve the specific VerifiableCredential object in asynchronous mode.
	 *
	 * <p>
	 * By default, this method will try to load the credential from the local
	 * cache, if the local cache not contains this credential, then try
	 * to resolve it from the ID chain.
	 * </p>
	 *
	 * @param id the id of the target credential
	 * @return a new CompletableStage, the result is the resolved
	 * 			VerifiableCredential object if success; null otherwise
	 */
	public static CompletableFuture<VerifiableCredential> resolveAsync(String id) {
		return resolveAsync(id, null, false);
	}

	/**
	 * Resolve all transaction of the specific credential.
	 *
	 * @param id the id of the target credential
	 * @param issuer optional, the issuer's did
	 * @return the resolved VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
	public static CredentialBiography resolveBiography(DIDURL id, DID issuer)
			throws DIDResolveException {
		checkArgument(id != null, "Invalid credential id");

		return DIDBackend.getInstance().resolveCredentialBiography(id, issuer);
	}

	/**
	 * Resolve all transaction of the specific credential.
	 *
	 * @param id the id of the target credential
	 * @return the resolved VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
	public static CredentialBiography resolveBiography(DIDURL id)
			throws DIDResolveException {
		checkArgument(id != null, "Invalid credential id");

		return DIDBackend.getInstance().resolveCredentialBiography(id);
	}

	/**
	 * Resolve all transaction of the specific credential.
	 *
	 * @param id the id of the target credential
	 * @param issuer optional, the issuer's did
	 * @return the resolved VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
	public static CredentialBiography resolveBiography(String id, String issuer)
			throws DIDResolveException {
		return resolveBiography(DIDURL.valueOf(id), DID.valueOf(issuer));
	}

	/**
	 * Resolve all transaction of the specific credential.
	 *
	 * @param id the id of the target credential
	 * @return the resolved VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
	public static CredentialBiography resolveBiography(String id)
			throws DIDResolveException {
		return resolveBiography(id, null);
	}

	/**
	 * Resolve all transaction of the specific credential in asynchronous mode.
	 *
	 * @param id the id of the target credential
	 * @param issuer optional, the issuer's did
	 * @return a new CompletableStage, the result is the resolved
	 * 			CredentialBiography object if success; null otherwise
	 */
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

	/**
	 * Resolve all transaction of the specific credential in asynchronous mode.
	 *
	 * @param id the id of the target credential
	 * @return a new CompletableStage, the result is the resolved
	 * 			CredentialBiography object if success; null otherwise
	 */
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

	/**
	 * Resolve all transaction of the specific credential in asynchronous mode.
	 *
	 * @param id the id of the target credential
	 * @param issuer optional, the issuer's did
	 * @return a new CompletableStage, the result is the resolved
	 * 			CredentialBiography object if success; null otherwise
	 */
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

	/**
	 * Resolve all transaction of the specific credential in asynchronous mode.
	 *
	 * @param id the id of the target credential
	 * @return a new CompletableStage, the result is the resolved
	 * 			CredentialBiography object if success; null otherwise
	 */
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

	/**
	 * List the published credentials that owned by the specific DID.
	 *
	 * @param did the did to be list
	 * @param skip set to skip N credentials ahead in this request
	 * 		  (useful for pagination).
	 * @param limit set the limit of credentials returned in the request
	 * 		  (useful for pagination).
	 * @return an array of DIDURL denoting the credentials
	 * @exception DIDResolveException if an error occurred when resolving the list
	 */
	public static List<DIDURL> list(DID did, int skip, int limit)
			throws DIDResolveException {
		checkArgument(did != null, "Invalid did");

		return DIDBackend.getInstance().listCredentials(did, skip, limit);
	}

	/**
	 * List the published credentials that owned by the specific DID.
	 *
	 * @param did the did to be list
	 * @param limit set the limit of credentials returned in the request
	 * 		  (useful for pagination).
	 * @return an array of DIDURL denoting the credentials
	 * @exception DIDResolveException if an error occurred when resolving the list
	 */
	public static List<DIDURL> list(DID did, int limit)
			throws DIDResolveException {
		checkArgument(did != null, "Invalid did");

		return DIDBackend.getInstance().listCredentials(did, 0, limit);
	}

	/**
	 * List the published credentials that owned by the specific DID.
	 *
	 * @param did the did to be list
	 * @return an array of DIDURL denoting the credentials
	 * @exception DIDResolveException if an error occurred when resolving the list
	 */
	public static List<DIDURL> list(DID did)
			throws DIDResolveException {
		checkArgument(did != null, "Invalid did");

		return DIDBackend.getInstance().listCredentials(did, 0, 0);
	}

	/**
	 * List the published credentials that owned by the specific DID in
	 * asynchronous mode.
	 *
	 * @param did the did to be list
	 * @param skip set to skip N credentials ahead in this request
	 * 		  (useful for pagination).
	 * @param limit set the limit of credentials returned in the request
	 * 		  (useful for pagination).
	 * @return a new CompletableStage, the result is an array of DIDURL
	 * 		   denoting the credentials
	 */
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

	/**
	 * List the published credentials that owned by the specific DID in
	 * asynchronous mode.
	 *
	 * @param did the did to be list
	 * @param limit set the limit of credentials returned in the request
	 * 		  (useful for pagination).
	 * @return a new CompletableStage, the result is an array of DIDURL
	 * 		   denoting the credentials
	 */
	public static CompletableFuture<List<DIDURL>> listAsync(DID did, int limit) {
		return listAsync(did, 0, limit);
	}

	/**
	 * List the published credentials that owned by the specific DID in
	 * asynchronous mode.
	 *
	 * @param did the did to be list
	 * @return a new CompletableStage, the result is an array of DIDURL
	 * 		   denoting the credentials
	 */
	public static CompletableFuture<List<DIDURL>> listAsync(DID did) {
		return listAsync(did, 0, 0);
	}

	/**
	 * Parse the VerifiableCredential object from a string JSON
	 * representation.
	 *
	 * @param content the string JSON content to deserialize the VerifiableCredential object
	 * @return the VerifiableCredential object
	 * @throws MalformedCredentialException if a parse error occurs
	 */
	public static VerifiableCredential parse(String content)
			throws MalformedCredentialException {
		try {
			return parse(content, VerifiableCredential.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedCredentialException)
				throw (MalformedCredentialException)e;
			else
				throw new MalformedCredentialException(e);
		}
	}

	/**
	 * Parse the VerifiableCredential object from a Reader object.
	 *
	 * @param src the Reader object to deserialize the VerifiableCredential object
	 * @return the VerifiableCredential object
	 * @throws MalformedCredentialException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static VerifiableCredential parse(Reader src)
			throws MalformedCredentialException, IOException {
		try {
			return parse(src, VerifiableCredential.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedCredentialException)
				throw (MalformedCredentialException)e;
			else
				throw new MalformedCredentialException(e);
		}
	}

	/**
	 * Parse the VerifiableCredential object from an input stream object.
	 *
	 * @param src the InputStream object to deserialize the VerifiableCredential object
	 * @return the VerifiableCredential object
	 * @throws MalformedCredentialException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static VerifiableCredential parse(InputStream src)
			throws MalformedCredentialException, IOException {
		try {
			return parse(src, VerifiableCredential.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedCredentialException)
				throw (MalformedCredentialException)e;
			else
				throw new MalformedCredentialException(e);
		}
	}

	/**
	 * Parse the VerifiableCredential object from a File object.
	 *
	 * @param src the File object to deserialize the VerifiableCredential object
	 * @return the VerifiableCredential object
	 * @throws MalformedCredentialException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static VerifiableCredential parse(File src)
			throws MalformedCredentialException, IOException {
		try {
			return parse(src, VerifiableCredential.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedCredentialException)
				throw (MalformedCredentialException)e;
			else
				throw new MalformedCredentialException(e);
		}
	}

	/**
	 * Parse the VerifiableCredential object from a string JSON
	 * representation.
	 *
	 * @param content the string representation of he credential object
	 * @return the VerifiableCredential object
	 * @throws MalformedCredentialException if a parse error occurs
	 * @deprecated use {@link #parse(String)} instead
	 */
	@Deprecated
	public static VerifiableCredential fromJson(String content)
			throws MalformedCredentialException {
		return parse(content);
	}

	/**
	 * Parse the VerifiableCredential object from a reader object.
	 *
	 * @param src the Reader object to deserialize the credential object
	 * @return the VerifiableCredential object
	 * @throws MalformedCredentialException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(Reader)} instead
	 */
	@Deprecated
	public static VerifiableCredential fromJson(Reader src)
			throws MalformedCredentialException, IOException {
		return parse(src);
	}

	/**
	 * Parse the VerifiableCredential object from an input stream object.
	 *
	 * @param src the InputStream object to deserialize the credential object
	 * @return the VerifiableCredential object
	 * @throws MalformedCredentialException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(InputStream)} instead
	 */
	@Deprecated
	public static VerifiableCredential fromJson(InputStream src)
			throws MalformedCredentialException, IOException {
		return parse(src);
	}

	/**
	 * Parse the VerifiableCredential object from a File object.
	 *
	 * @param src the File object to deserialize the credential object
	 * @return the VerifiableCredential object
	 * @throws MalformedCredentialException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(File)} instead
	 */
	@Deprecated
	public static VerifiableCredential fromJson(File src)
			throws MalformedCredentialException, IOException {
		return parse(src);
	}

	/**
	 * The Builder object is a helper class to create a credential object.
	 *
	 * The credential object is immutable object. After set the contents for new
	 * credential, should call seal {@link Builder#seal(String)} method to
	 * create the final credential object.
	 */
	public static class Builder {
		private Issuer issuer;
		private DID target;

		private VerifiableCredential credential;

		/**
		 * Create a credential builder.
		 *
		 * @param issuer the credential issuer object
		 * @param target who the new credential issue to
		 */
		protected Builder(Issuer issuer, DID target) {
			this.issuer = issuer;
			this.target = target;

			credential = new VerifiableCredential();
			credential.issuer = issuer.getDid();
			credential.subject = new Subject(target);
		}

		private void checkNotSealed() throws AlreadySealedException {
			if (credential == null)
				throw new AlreadySealedException();
		}

		/**
		 * Set the credential id.
		 *
		 * @param id the credential id
		 * @return the Builder instance for method chaining
		 */
		public Builder id(DIDURL id) {
			checkNotSealed();
			checkArgument(id != null && (id.getDid() == null || id.getDid().equals(target)),
					"Invalid id");

			if (id.getDid() == null)
				id = new DIDURL(target, id);

			credential.id = id;
			return this;
		}

		/**
		 * Set the credential id.
		 *
		 * @param id the credential id
		 * @return the Builder instance for method chaining
		 */
		public Builder id(String id) {
			return id(DIDURL.valueOf(target, id));
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

			credential.type = new ArrayList<String>(Arrays.asList(types));
			Collections.sort(credential.type);
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
			checkNotSealed();

			credential.expirationDate = getMaxExpires().getTime();
			return this;
		}

		/**
		 * Set expire time for the credential.
		 *
		 * @param expirationDate the expires time
		 * @return the Builder instance for method chaining
		 */
		public Builder expirationDate(Date expirationDate) {
			checkNotSealed();
			checkArgument(expirationDate != null, "Invalid expiration date");

			Calendar cal = Calendar.getInstance(Constants.UTC);
			cal.setTime(expirationDate);

			Calendar maxExpires = getMaxExpires();
			if (cal.after(maxExpires))
				cal = maxExpires;

			credential.expirationDate = cal.getTime();

			return this;
		}

		/**
		 * Set the claim properties to the credential subject from a map object.
		 *
		 * @param properties a map object include the claims
		 * @return the Builder instance for method chaining
		 */
		public Builder properties(Map<String, Object> properties) {
			checkNotSealed();

			credential.subject.properties.clear();

			if (properties == null || properties.size() == 0)
				return this;

			credential.subject.properties.putAll(properties);
			credential.subject.properties.remove(ID);
			return this;
		}

		/**
		 * Set the claim properties to the credential subject from JSON data.
		 *
		 * @param json the JSON string include the claims
		 * @return the Builder instance for method chaining
		 */
		public Builder properties(String json) {
			checkNotSealed();
			checkArgument(json != null && !json.isEmpty(), "Invalid json");

			ObjectMapper mapper = getObjectMapper();
			try {
				Map<String, Object> props = mapper.readValue(json,
						new TypeReference<Map<String, Object>>() {});
				return properties(props);
			} catch (JsonProcessingException e) {
				throw new IllegalArgumentException("Invalid json", e);
			}

		}

		/**
		 * Add new claim property to the credential subject.
		 *
		 * @param name the property name
		 * @param value the property value
		 * @return the Builder instance for method chaining
		 */
		public Builder property(String name, Object value) {
			checkNotSealed();
			checkArgument(name != null && !name.isEmpty() && !name.equals(ID), "Invalid name");

			credential.subject.setProperty(name, value);
			return this;
		}

		private void sanitize() throws MalformedCredentialException {
			if (credential.id == null)
				throw new MalformedCredentialException("Missing credential id");

			if (credential.type == null || credential.type.isEmpty())
				throw new MalformedCredentialException("Missing credential type");

			Calendar cal = Calendar.getInstance(Constants.UTC);
			credential.issuanceDate = cal.getTime();

			if (!credential.hasExpirationDate())
				defaultExpirationDate();

			credential.proof = null;
		}

		/**
		 * Seal the credential object, attach the generated proof to the
		 * credential.
		 *
		 * @param storepass the password for DIDStore
		 * @return the sealed credential object
		 * @throws MalformedCredentialException if the Credential is malformed
		 * @throws DIDStoreException if an error occurs when accessing the DID store
		 */
		public VerifiableCredential seal(String storepass)
				throws MalformedCredentialException, DIDStoreException {
			checkNotSealed();
			checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

			sanitize();

			String json = credential.serialize(true);
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
