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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import org.elastos.did.exception.DIDBackendException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.MalformedCredentialException;
import org.elastos.did.metadata.CredentialMetadataImpl;
import org.elastos.did.util.JsonHelper;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class VerifiableCredential extends DIDObject {
	protected final static String ID = "id";
	private final static String TYPE = "type";
	private final static String ISSUER = "issuer";
	private final static String ISSUANCE_DATE = "issuanceDate";
	private final static String EXPIRATION_DATE = "expirationDate";
	private final static String CREDENTIAL_SUBJECT = "credentialSubject";
	private final static String PROOF = "proof";
	private final static String VERIFICATION_METHOD = "verificationMethod";
	private final static String SIGNATURE = "signature";

	private final static String DEFAULT_PUBLICKEY_TYPE = Constants.DEFAULT_PUBLICKEY_TYPE;

	private List<String> types;
	private DID issuer;
	private Date issuanceDate;
	private Date expirationDate;
	private CredentialSubject subject;
	private Proof proof;

	private CredentialMetadataImpl metadata;

	static public class CredentialSubject {
		private DID id;
		private ObjectNode properties;

		/**
		 * Constructs the CredentialSubject object with given value.
		 *
		 * @param id the owner of Credential Subject
		 */
		protected CredentialSubject(DID id) {
			this.id = id;
		}

		/**
		 * Get the owner of Credential Subject
		 *
		 * @return the owner
		 */
		public DID getId() {
			return id;
		}

		/**
		 * Get the count of Credential Subject.
		 *
		 * @return the count
		 */
		public int getPropertyCount() {
			return properties.size();
		}

		/**
		 * Get Credential Subject with string format.
		 *
		 * @return the properties string
		 */
		public String getPropertiesAsString() {
			return properties.toString();
		}

		/**
		 * Get Credential Subject with JsonNode format.
		 *
		 * @return the properties json node
		 */
		public JsonNode getProperties() {
			return properties.deepCopy();
		}

		/**
		 * Get the specified property of Credential Subject.
		 *
		 * @param name the 'name' property
		 * @return the property value string
		 */
		public String getPropertyAsString(String name) {
			return properties.get(name).asText();
		}

		/**
		 * Get the specified property of Credential Subject.
		 *
		 * @param name the 'name' property
		 * @return the property value json node
		 */
		public JsonNode getProperty(String name) {
			return properties.get(name).deepCopy();
		}

		/**
		 * Set Credential Subject with the given value.
		 *
		 * @param props the properties json node
		 */
		protected void setProperties(JsonNode props) {
			properties = props.deepCopy();
			// remote ID field, avoid conflict with subject's id property.
			properties.remove(ID);
		}

		/**
		 * Get Credential Subject from json.
		 *
		 * @param node the Credential json node
		 * @param ref the owner of Credential
		 * @return the CredentialSubject object
		 * @throws MalformedCredentialException Credential is malformed.
		 */
		protected static CredentialSubject fromJson(JsonNode node, DID ref)
				throws MalformedCredentialException {
			Class<MalformedCredentialException> clazz = MalformedCredentialException.class;

			// id
			DID id = JsonHelper.getDid(node, ID, ref != null, ref,
					"crendentialSubject id", clazz);

			CredentialSubject cs = new CredentialSubject(id);

			// Properties
			cs.setProperties(node);

			return cs;
		}

		/**
		 * Get Credential json string
		 *
		 * @param generator the JsonGenerator handle
		 * @param ref the owner of Credential
		 * @param normalized json string is normalized or compact
		 * @throws IOException write credential json failed.
		 */
		protected void toJson(JsonGenerator generator, DID ref, boolean normalized)
				throws IOException {
			generator.writeStartObject();

			// id
			if (normalized || ref == null || !getId().equals(ref)) {
				generator.writeFieldName(ID);
				generator.writeString(getId().toString());
			}

			// Properties
			if (properties != null)
				JsonHelper.toJson(generator, properties, true);

			generator.writeEndObject();
		}

	}

	static public class Proof {
		private String type;
		private DIDURL verificationMethod;
		private String signature;

		/**
		 * Constructs the Credential Proof with the given value.
		 *
		 * @param type the Proof tye
		 * @param method the sign key
		 * @param signature the signature string
		 */
		protected Proof(String type, DIDURL method, String signature) {
			this.type = type;
			this.verificationMethod = method;
			this.signature = signature;
		}

		/**
		 * Get the type of Credential Proof.
		 *
		 * @return the type string
		 */
	    public String getType() {
	    	return type;
	    }

	    /**
	     * Get the key to sign Credential Proof.
	     *
	     * @return the sign key
	     */
	    public DIDURL getVerificationMethod() {
	    	return verificationMethod;
	    }

	    /**
	     * Get the signature string.
	     *
	     * @return the signature string
	     */
	    public String getSignature() {
	    	return signature;
	    }

	    /**
	     * Get Credential Proof from json string
	     *
	     * @param node the json node content
	     * @param ref the owner of Credential
	     * @return the Credential Proof object
	     * @throws MalformedCredentialException Credential is malformed.
	     */
		protected static Proof fromJson(JsonNode node, DID ref)
				throws MalformedCredentialException {
			Class<MalformedCredentialException> clazz = MalformedCredentialException.class;

			String type = JsonHelper.getString(node, TYPE, true,
					DEFAULT_PUBLICKEY_TYPE, "crendential proof type", clazz);

			DIDURL method = JsonHelper.getDidUrl(node, VERIFICATION_METHOD, ref,
					"crendential proof verificationMethod", clazz);

			String signature = JsonHelper.getString(node, SIGNATURE,
					false, null, "crendential proof signature", clazz);

			return new Proof(type, method, signature);
		}

		/**
		 * Get Credential Subject's json string.
		 *
		 * @param generator the JsonGenerator handle
		 * @param ref the owner of Credential
		 * @param normalized json string is normalized or compact
		 * @throws IOException write json string failed.
		 */
		protected void toJson(JsonGenerator generator, DID ref, boolean normalized)
				throws IOException {
			generator.writeStartObject();

			// type
			if (normalized || !type.equals(DEFAULT_PUBLICKEY_TYPE)) {
				generator.writeFieldName(TYPE);
				generator.writeString(type);
			}

			// method
			String value;
			generator.writeFieldName(VERIFICATION_METHOD);
			if (normalized || ref == null || !verificationMethod.getDid().equals(ref))
				value = verificationMethod.toString();
			else
				value = "#" + verificationMethod.getFragment();
			generator.writeString(value);

			// signature
			generator.writeFieldName(SIGNATURE);
			generator.writeString(signature);

			generator.writeEndObject();
		}
	}

	/**
	 * Constructs the empty Credentila object.
	 */
	protected VerifiableCredential() {
		super(null, null);
	}

	/**
	 * Constructs a new Credentila object with the given object.
	 *
	 * @param vc the Credential object
	 */
	protected VerifiableCredential(VerifiableCredential vc) {
		setId(vc.getId());

		this.types = vc.types;
		this.issuer = vc.issuer;
		this.issuanceDate = vc.issuanceDate;
		this.expirationDate = vc.expirationDate;
		this.subject = vc.subject;
		this.proof = vc.proof;
	}

	@Override
	protected void setId(DIDURL id) {
		super.setId(id);
	}

	@Override
	public String getType() {
		StringBuilder builder = new StringBuilder(512);
		boolean initial = true;

		builder.append("[");

		if (types != null) {
			for (String t : types) {
				if (initial)
					initial = false;
				else
					builder.append(", ");

				builder.append(t);
			}
		}

		builder.append("]");

		return builder.toString();
	}

	/**
	 * Get the types of Credential Proof.
	 *
	 * @return the type array
	 */
	public String[] getTypes() {
		return types == null ? null : types.toArray(new String[0]);
	}

	/**
	 * Add type to Credential Proof.
	 *
	 * @param type the type string
	 */
	protected void addType(String type) {
		if (types == null)
			types = new ArrayList<String>(4);

		types.add(type);
	}

	/**
	 * Set types to Credential Proof.
	 *
	 * @param type the type array
	 */
	protected void setType(String[] type) {
		if (types == null)
			types = new ArrayList<String>(type.length);

		for (String t : type)
			types.add(t);
	}

	/**
	 * Get issuer of Credential.
	 *
	 * @return the issuer's DID
	 */
	public DID getIssuer() {
		return issuer;
	}

	/**
	 * Set Issuer of Credential.
	 *
	 * @param issuer the issuer's DID
	 */
	protected void setIssuer(DID issuer) {
		this.issuer = issuer;
	}

	/**
	 * Get the time issued Credential.
	 *
	 * @return the time to issue Credential
	 */
	public Date getIssuanceDate() {
		return issuanceDate;
	}

	/**
	 * Set the time issued Credential.
	 *
	 * @param issuanceDate the time to issue Credential
	 */
	protected void setIssuanceDate(Date issuanceDate) {
		this.issuanceDate = issuanceDate;
	}

	/**
	 * Judge that there is expires time or not.
	 *
	 * @return the returned value is true if there is expires time;
	 *         the returned value is false if there is no expires time.
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
	 * Set meta data for Credential.
	 *
	 * @param metadata the meta data object
	 */
	protected void setMetadata(CredentialMetadataImpl metadata) {
		this.metadata = metadata;
		this.getId().setMetadata(metadata);
	}

	/**
	 * Get meta data implemention object from Credential.
	 *
	 * @return the Credential Meta data object
	 */
	protected CredentialMetadataImpl getMetadataImpl() {
		if (metadata == null) {
			metadata = new CredentialMetadataImpl();
			getId().setMetadata(metadata);
		}

		return metadata;
	}

	/**
	 * Get Meta data from Credential.
	 *
	 * @return the Credential Meta data object
	 */
	public CredentialMetadata getMetadata() {
		return getMetadataImpl();
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
	 * Judge whether the Credential is self proclaimed one or not.
	 *
	 * @return the returned value is true if the Credential is self proclaimed;
	 *         the returned value is false if the Credential is not self proclaimed.
	 */
	public boolean isSelfProclaimed() {
		return issuer.equals(subject.id);
	}

	private static final int RULE_EXPIRE = 1;
	private static final int RULE_GENUINE = 2;
	private static final int RULE_VALID = 3;

	private boolean traceCheck(int rule)
			throws DIDResolveException, DIDBackendException {
		DIDDocument controllerDoc = subject.id.resolve();
		if (controllerDoc == null)
			return false;

		switch (rule) {
		case RULE_EXPIRE:
			if (controllerDoc.isExpired())
				return true;
			break;

		case RULE_GENUINE:
			if (!controllerDoc.isGenuine())
				return false;
			break;

		case RULE_VALID:
			if (!controllerDoc.isValid())
				return false;
			break;
		}

		if (!isSelfProclaimed()) {
			DIDDocument issuerDoc = issuer.resolve();
			switch (rule) {
			case RULE_EXPIRE:
				if (issuerDoc.isExpired())
					return true;
				break;

			case RULE_GENUINE:
				if (!issuerDoc.isGenuine())
					return false;
				break;

			case RULE_VALID:
				if (!issuerDoc.isValid())
					return false;
				break;
			}
		}

		return rule != RULE_EXPIRE;
	}

	private boolean checkExpired() {
		if (expirationDate != null) {
			Calendar now = Calendar.getInstance(Constants.UTC);

			Calendar expireDate  = Calendar.getInstance(Constants.UTC);
			expireDate.setTime(expirationDate);

			return now.after(expireDate);
		}

		return false;
	}

	/**
	 * Judge whether the Credential is expired or not.
	 *
	 * @return the returned value is true if the Credential is expired;
	 *         the returned value is false if the Credential is not expired.
	 * @throws DIDResolveException get the lastest document from chain failed.
	 * @throws DIDBackendException get content from net failed.
	 */
	public boolean isExpired() throws DIDResolveException, DIDBackendException {
		if (traceCheck(RULE_EXPIRE))
			return true;

		return checkExpired();
	}

	/**
	 * Judge whether the Credential is expired or not with asynchronous mode.
	 *
	 * @return the new CompletableStage, the result is the boolean interface for
	 *         expires judgement if success; null otherwise.
	 */
	public CompletableFuture<Boolean> isExpiredAsync() {
		CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
			try {
				return isExpired();
			} catch (DIDBackendException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	private boolean checkGenuine() throws DIDResolveException, DIDBackendException {
		DIDDocument issuerDoc = issuer.resolve();

		// Credential should signed by authentication key.
		if (!issuerDoc.isAuthenticationKey(proof.getVerificationMethod()))
			return false;

		// Unsupported public key type;
		if (!proof.getType().equals(DEFAULT_PUBLICKEY_TYPE))
			return false;

		String json = toJson(true, true);

		return issuerDoc.verify(proof.getVerificationMethod(),
				proof.getSignature(), json.getBytes());
	}

	/**
	 * Check whether the Credential is genuine or not.
	 *
	 * @return the returned value is true if the Credential is genuine;
	 *         the returned value is false if the Credential is not genuine.
	 * @throws DIDResolveException get the lastest document from chain failed.
	 * @throws DIDBackendException get content from net failed.
	 */
	public boolean isGenuine() throws DIDResolveException, DIDBackendException {
		if (!traceCheck(RULE_GENUINE))
			return false;

		return checkGenuine();
	}

	/**
	 * Check whether the Credential is genuine or not with asynchronous mode.
	 *
	 * @return the new CompletableStage, the result is the boolean interface for
	 *         genuine judgement if success; null otherwise.
	 */
	public CompletableFuture<Boolean> isGenuineAsync() {
		CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
			try {
				return isGenuine();
			} catch (DIDBackendException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Check whether the Credential is valid or not.
	 *
	 * @return the returned value is true if the Credential is valid;
	 *         the returned value is false if the Credential is not valid.
	 * @throws DIDResolveException get the lastest document from chain failed.
	 * @throws DIDBackendException get content from net failed.
	 */
	public boolean isValid() throws DIDResolveException, DIDBackendException {
		if (!traceCheck(RULE_VALID))
			return false;

		return !checkExpired() && checkGenuine();
	}

	/**
	 * Check whether the Credential is valid or not.
	 *
	 * @return the new CompletableStage, the result is the boolean interface for
	 *         valid judgement if success; null otherwise.
	 */
	public CompletableFuture<Boolean> isValidAsync() {
		CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
			try {
				return isValid();
			} catch (DIDBackendException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Set expires time for Credential.
	 *
	 * @param expirationDate the expires time
	 */
	protected void setExpirationDate(Date expirationDate) {
		this.expirationDate = expirationDate;
	}

	/**
	 * Get Credential subject content.
	 *
	 * @return the Credential Subject object
	 */
	public CredentialSubject getSubject() {
		return subject;
	}

	/**
	 * Set Credential subject content.
	 *
	 * @param subject the CredentialSubject object
	 */
	protected void setSubject(CredentialSubject subject) {
		this.subject = subject;
	}

	/**
	 * Get Credential proof content.
	 *
	 * @return the Credential Proof object
	 */
	public Proof getProof() {
		return proof;
	}

	/**
	 * Set Credential proof content.
	 *
	 * @param proof the Credential Proof object
	 */
	protected void setProof(Proof proof) {
		this.proof = proof;
	}

	/**
	 * Check the basic element for Credential.
	 *
	 * @throws MalformedCredentialException the Credential is malformed.
	 */
	protected void completeCheck() throws MalformedCredentialException {
		if (getId() == null) // TODO:
			throw new MalformedCredentialException("Missing id.");

		if (getTypes() == null) // TODO:
			throw new MalformedCredentialException("Missing types.");

		if (subject == null || subject.id == null)
			throw new MalformedCredentialException("Missing subject.");
	}

	private void parse(Reader reader) throws MalformedCredentialException {
		ObjectMapper mapper = new ObjectMapper();
		try {
			JsonNode node = mapper.readTree(reader);
			parse(node, null);
		} catch (IOException e) {
			throw new MalformedCredentialException("Parse JSON document error.", e);
		}
	}

	private void parse(InputStream in) throws MalformedCredentialException {
		ObjectMapper mapper = new ObjectMapper();
		try {
			JsonNode node = mapper.readTree(in);
			parse(node, null);
		} catch (IOException e) {
			throw new MalformedCredentialException("Parse JSON document error.", e);
		}
	}

	private void parse(String json) throws MalformedCredentialException {
		ObjectMapper mapper = new ObjectMapper();
		try {
			JsonNode node = mapper.readTree(json);
			parse(node, null);
		} catch (IOException e) {
			throw new MalformedCredentialException("Parse JSON document error.", e);
		}
	}

	private void parse(JsonNode node, DID ref) throws MalformedCredentialException {
		Class<MalformedCredentialException> clazz = MalformedCredentialException.class;

		// type
		JsonNode valueNode = node.get(TYPE);
		if (valueNode == null)
			throw new MalformedCredentialException("Missing credential type.");

		if (!valueNode.isArray() || valueNode.size() == 0)
			throw new MalformedCredentialException(
					"Invalid credential type, should be an array.");

		for (int i = 0; i < valueNode.size(); i++) {
			String t = valueNode.get(i).asText();
			if (t != null && !t.isEmpty())
				addType(t);
		}

		// issuer
		issuer = JsonHelper.getDid(node, ISSUER,
				true, ref, "crendential issuer", clazz);

		// issuanceDate
		issuanceDate = JsonHelper.getDate(node, ISSUANCE_DATE,
				false, null, "credential issuanceDate", clazz);

		// expirationDate
		expirationDate = JsonHelper.getDate(node, EXPIRATION_DATE,
				true, null, "credential expirationDate", clazz);

		// credentialSubject
		valueNode = node.get(CREDENTIAL_SUBJECT);
		if (valueNode == null)
			throw new MalformedCredentialException("Missing credentialSubject.");
		subject = CredentialSubject.fromJson(valueNode, ref);

		// id
		DIDURL id = JsonHelper.getDidUrl(node, ID,
				ref != null ? ref : subject.getId(), "crendential id", clazz);
		setId(id);

		// IMPORTANT: help resolve full method in proof
		if (issuer == null)
			issuer = subject.getId();

		// proof
		valueNode = node.get(PROOF);
		if (valueNode == null)
			throw new MalformedCredentialException("Missing credential proof.");
		proof = Proof.fromJson(valueNode, issuer);
	}

	/**
	 * Get Credential from input content.
	 *
	 * @param reader the Reader content
	 * @return the Credential object
	 * @throws MalformedCredentialException the Credential is malfromed.
	 */
	public static VerifiableCredential fromJson(Reader reader)
			throws MalformedCredentialException {
		if (reader == null)
			throw new IllegalArgumentException();

		VerifiableCredential vc = new VerifiableCredential();
		vc.parse(reader);

		return vc;
	}

	/**
	 * Get Credential from input content.
	 *
	 * @param in the InputStream content
	 * @return the Credential object
	 * @throws MalformedCredentialException the Credential is malfromed.
	 */
	public static VerifiableCredential fromJson(InputStream in)
			throws MalformedCredentialException {
		if (in == null)
			throw new IllegalArgumentException();

		VerifiableCredential vc = new VerifiableCredential();
		vc.parse(in);

		return vc;
	}

	/**
	 * Get Credential from input content.
	 *
	 * @param json the json string content
	 * @return the Credential object
	 * @throws MalformedCredentialException the Credential is malfromed.
	 */
	public static VerifiableCredential fromJson(String json)
			throws MalformedCredentialException {
		if (json == null || json.isEmpty())
			throw new IllegalArgumentException();

		VerifiableCredential vc = new VerifiableCredential();
		vc.parse(json);

		return vc;
	}

	/**
	 * Get Credential from input content.
	 *
	 * @param node the JsonNode content
	 * @param ref the owner of Credential
	 * @return the Credential object
	 * @throws MalformedCredentialException the Credential is malfromed.
	 */
	protected static VerifiableCredential fromJson(JsonNode node, DID ref)
			throws MalformedCredentialException {
		VerifiableCredential vc = new VerifiableCredential();
		vc.parse(node, ref);
		return vc;
	}

	/**
	 * Get Credential from input content.
	 *
	 * @param node the JsonNode content
	 * @return the Credential object
	 * @throws MalformedCredentialException the Credential is malfromed.
	 */
	protected static VerifiableCredential fromJson(JsonNode node)
			throws MalformedCredentialException {
		return fromJson(node, null);
	}

	/**
	 * Get json content of Credential.
	 *
	 * @param generator the JsonGenerator handle
	 * @param ref the owner of Credential
	 * @param normalized json string is normalized or compact.
	 * @throws IOException  write field to json string failed.
	 */
	protected void toJson(JsonGenerator generator, DID ref, boolean normalized)
			throws IOException {
		toJson(generator, ref, normalized, false);
	}

	/**
	 * Get json content of Credential.
	 *
	 * @param generator the JsonGenerator handle
	 * @param normalized json string is normalized or compact.
	 * @throws IOException  write field to json string failed.
	 */
	protected void toJson(JsonGenerator generator, boolean normalized)
			throws IOException {
		toJson(generator, null, normalized);
	}

	/**
	 * Get json content of Credential.
	 *
	 * Normalized serialization order:
	 * - id
	 * - type ordered names array(case insensitive/ascending)
	 * - issuer
	 * - issuanceDate
	 * - expirationDate
	 * + credentialSubject
	 *   - id
	 *   - properties ordered by name(case insensitive/ascending)
	 * + proof
	 *   - type
	 *   - method
	 *   - signature
     *
	 * @param generator the JsonGenerator handle
	 * @param ref the owner of Credential
	 * @param normalized json string is normalized or compact.
	 * @param forSign = true, only generate json string without proof;
	 *        forSign = false, getnerate json string the whole credential.
	 * @throws IOException write field to json string failed.
	 */
	protected void toJson(JsonGenerator generator, DID ref, boolean normalized,
			boolean forSign) throws IOException {
		generator.writeStartObject();

		// id
		String value;
		generator.writeFieldName(ID);

		if (normalized || ref == null || !getId().getDid().equals(ref))
			value = getId().toString();
		else
			value = "#" + getId().getFragment();

		generator.writeString(value);

		// type
		generator.writeFieldName(TYPE);
		generator.writeStartArray();
		Collections.sort(types);
		for (String s : types) {
			generator.writeString(s);
		}
		generator.writeEndArray();

		// issuer
		if (normalized || !issuer.equals(subject.getId())) {
			generator.writeFieldName(ISSUER);
			generator.writeString(issuer.toString());
		}

		// issuanceDate
		generator.writeFieldName(ISSUANCE_DATE);
		generator.writeString(JsonHelper.formatDate(issuanceDate));

		// expirationDate
		if (expirationDate != null) {
			generator.writeFieldName(EXPIRATION_DATE);
			generator.writeString(JsonHelper.formatDate(expirationDate));
		}

		// credentialSubject
		generator.writeFieldName(CREDENTIAL_SUBJECT);
		subject.toJson(generator, ref, normalized);

		// proof
		if (!forSign ) {
			generator.writeFieldName(PROOF);
			proof.toJson(generator, issuer, normalized);
		}

		generator.writeEndObject();
	}

	/**
	 * Get json content of Credential.
	 *
	 * @param out the Writer handle
	 * @param normalized json string is normalized or compact.
	 * @throws IOException write field to json string failed.
	 */
	public void toJson(Writer out, boolean normalized) throws IOException {
		toJson(out, normalized, false);
	}

	/**
	 * Get json content of Credential.
	 *
	 * @param out the Writer handle
	 * @param normalized json string is normalized or compact.
	 * @param forSign = true, only generate json string without proof;
	 *        forSign = false, getnerate json string the whole credential.
	 * @throws IOException write field to json string failed.
	 */
	protected void toJson(Writer out, boolean normalized, boolean forSign)
			throws IOException {
		if (out == null)
			throw new IllegalArgumentException();

		JsonFactory factory = new JsonFactory();
		JsonGenerator generator = factory.createGenerator(out);

		toJson(generator, null, normalized, forSign);

		generator.close();
	}

	/**
	 * Get json content of Credential.
	 *
	 * @param out the OutputStream handle
	 * @param charsetName encode using this charset
	 * @param normalized json string is normalized or compact.
	 * @throws IOException write field to json string failed.
	 */
	public void toJson(OutputStream out, String charsetName, boolean normalized)
			throws IOException {
		if (out == null)
			throw new IllegalArgumentException();

		toJson(new OutputStreamWriter(out, charsetName), normalized);
	}

	/**
	 * Get json content of Credential.
	 *
	 * @param out the OutputStream handle
	 * @param normalized json string is normalized or compact.
	 * @throws IOException write field to json string failed.
	 */
	public void toJson(OutputStream out, boolean normalized) throws IOException {
		if (out == null)
			throw new IllegalArgumentException();

		toJson(new OutputStreamWriter(out), normalized);
	}

	/**
	 * Get json content of Credential.
	 *
	 * @param normalized json string is normalized or compact.
	 * @param forSign = true, only generate json string without proof;
	 *        forSign = false, getnerate json string the whole credential.
	 * @return the Credential's json string
	 */
	protected String toJson(boolean normalized, boolean forSign) {
		Writer out = new StringWriter(2048);

		try {
			toJson(out, normalized, forSign);
		} catch (IOException ignore) {
			ignore.printStackTrace();
		}

		return out.toString();
	}

	/**
	 * Get json string of Credential .
	 *
	 * @param normalized json string is normalized or compact.
	 * @return the json string
	 */
	public String toString(boolean normalized) {
		return toJson(normalized, false);
	}

	@Override
	public String toString() {
		return toString(false);
	}
}
