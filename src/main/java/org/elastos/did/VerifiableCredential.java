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
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import org.elastos.did.exception.DIDBackendException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.MalformedCredentialException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

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
public class VerifiableCredential extends DIDObject<VerifiableCredential> implements DIDEntry {
	protected final static String ID = "id";
	protected final static String TYPE = "type";
	protected final static String ISSUER = "issuer";
	protected final static String ISSUANCE_DATE = "issuanceDate";
	protected final static String EXPIRATION_DATE = "expirationDate";
	protected final static String CREDENTIAL_SUBJECT = "credentialSubject";
	protected final static String PROOF = "proof";
	protected final static String VERIFICATION_METHOD = "verificationMethod";
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
	@JsonPropertyOrder({ TYPE, VERIFICATION_METHOD, SIGNATURE })
	static public class Proof {
		@JsonProperty(TYPE)
		private String type;
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
				@JsonProperty(value = SIGNATURE, required = true) String signature) {
			this.type = type != null ? type : Constants.DEFAULT_PUBLICKEY_TYPE;
			this.verificationMethod = method;
			this.signature = signature;
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
	     * Get the signature.
	     *
	     * @return the signature encoded in URL safe base64 string
	     */
	    public String getSignature() {
	    	return signature;
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
		if (metadata == null) {
			metadata = new CredentialMetadata();
			getId().setMetadata(metadata);
		}

		return metadata;
	}

	/**
	 * Store Meta data of Credential.
	 *
	 * @throws DIDStoreException store meta data failed.
	 */
	public void saveMetadata() throws DIDStoreException {
		if (metadata != null && metadata.attachedStore())
			metadata.getStore().storeCredentialMetadata(getSubject().getId(),
					getId(), metadata);
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
		DIDDocument issuerDoc = issuer.resolve();

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
			log.error("INTERAL - serialize credential", ignore);
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
			log.error("INTERAL - serialize credential", ignore);
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
	 * @deprecated use {@link #parse(String))} instead
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
	 * @deprecated use {@link #parse(Reader))} instead
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
	 * @deprecated use {@link #parse(InputStream))} instead
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
	 * @deprecated use {@link #parse(File))} instead
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
	 * credential, should call seal {@see Builder#seal(String)} method to
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

			if (id == null)
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

			DIDURL _id = id == null ? null : new DIDURL(target, id);
			return id(_id);
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
		 * @param node the subject subject with JsonNode format
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

			Proof proof = new Proof(Constants.DEFAULT_PUBLICKEY_TYPE, issuer.getSignKey(), sig);
			credential.proof = proof;

			// Invalidate builder
			VerifiableCredential vc = credential;
			this.credential = null;

			return vc;
		}
	}
}
