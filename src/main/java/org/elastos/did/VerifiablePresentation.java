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
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import org.elastos.did.exception.DIDBackendException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.MalformedCredentialException;
import org.elastos.did.exception.MalformedPresentationException;
import org.elastos.did.util.JsonHelper;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class VerifiablePresentation {
	public final static String DEFAULT_PRESENTATION_TYPE = "VerifiablePresentation";

	private final static String TYPE = "type";
	private final static String VERIFIABLE_CREDENTIAL = "verifiableCredential";
	private final static String CREATED = "created";
	private final static String PROOF = "proof";
	private final static String NONCE = "nonce";
	private final static String REALM = "realm";
	private final static String VERIFICATION_METHOD = "verificationMethod";
	private final static String SIGNATURE = "signature";

	private final static String DEFAULT_PUBLICKEY_TYPE = Constants.DEFAULT_PUBLICKEY_TYPE;

	private String type;
	private Date created;
	private Map<DIDURL, VerifiableCredential> credentials;
	private Proof proof;

	static public class Proof {
		private String type;
		private DIDURL verificationMethod;
		private String realm;
		private String nonce;
		private String signature;

		protected Proof(String type, DIDURL method, String realm,
				String nonce, String signature) {
			this.type = type;
			this.verificationMethod = method;
			this.realm = realm;
			this.nonce = nonce;
			this.signature = signature;
		}

		/**
		 * Constructs the Presentation Proof with the given value.
		 *
		 * @param method the sign key
		 * @param realm where is Presentation use
		 * @param nonce the nonce string
		 * @param signature the signature string
		 */
		protected Proof(DIDURL method, String realm,
				String nonce, String signature) {
			this(DEFAULT_PUBLICKEY_TYPE, method, realm, nonce, signature);
		}

		/**
		 * Get type of Presentation.
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

	    /**
	     * Get Presentation Proof from input content.
	     *
	     * @param node the JsonNode content
	     * @param ref the owner of Presentation
	     * @return the Credential Proof object
	     * @throws MalformedPresentationException the presentation is malformed.
	     */
		protected static Proof fromJson(JsonNode node, DID ref)
				throws MalformedPresentationException {
			Class<MalformedPresentationException> clazz = MalformedPresentationException.class;

			String type = JsonHelper.getString(node, TYPE, true,
					DEFAULT_PUBLICKEY_TYPE, "presentation proof type", clazz);

			DIDURL method = JsonHelper.getDidUrl(node, VERIFICATION_METHOD, ref,
					"presentation proof verificationMethod", clazz);

			String realm = JsonHelper.getString(node, REALM,
					false, null, "presentation proof realm", clazz);

			String nonce = JsonHelper.getString(node, NONCE,
					false, null, "presentation proof nonce", clazz);

			String signature = JsonHelper.getString(node, SIGNATURE,
					false, null, "presentation proof signature", clazz);

			return new Proof(type, method, realm, nonce, signature);
		}

		/**
		 * Get json content of Presentation.
		 *
		 * @param generator the JsonGenerator handle
		 * @throws IOException write field to json string failed.
		 */
		protected void toJson(JsonGenerator generator) throws IOException {
			generator.writeStartObject();

			// type
			generator.writeFieldName(TYPE);
			generator.writeString(type);

			// method
			generator.writeFieldName(VERIFICATION_METHOD);
			generator.writeString(verificationMethod.toString());

			// realm
			generator.writeFieldName(REALM);
			generator.writeString(realm);

			// nonce
			generator.writeFieldName(NONCE);
			generator.writeString(nonce);

			// signature
			generator.writeFieldName(SIGNATURE);
			generator.writeString(signature);

			generator.writeEndObject();
		}
	}

	/**
	 * Constructs the simplest Presentation.
	 */
	protected VerifiablePresentation() {
		type = DEFAULT_PRESENTATION_TYPE;

		Calendar cal = Calendar.getInstance(Constants.UTC);
		created = cal.getTime();

		credentials = new TreeMap<DIDURL, VerifiableCredential>();
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
	 * Set the type of Presentation.
	 *
	 * @return the type string
	 */
	protected void setType(String type) {
		this.type = type;
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
	 * Set the time created Presentation.
	 *
	 * @return the time created
	 */
	protected void setCreated(Date created) {
		this.created = created;
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
		List<VerifiableCredential> lst = new ArrayList<VerifiableCredential>(
				credentials.size());

		lst.addAll(credentials.values());
		return lst;
	}

	/**
	 * Add the Credential to Presentation.
	 *
	 * @param credential the Credential object
	 */
	protected void addCredential(VerifiableCredential credential) {
		credentials.put(credential.getId(), credential);
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
	 * Get signer of Presentation.
	 *
	 * @return the signer's DID
	 */
	public DID getSigner() {
		return proof.getVerificationMethod().getDid();
	}

	/**
	 * Check whether the Presentation is genuine or not.
	 *
	 * @return the returned value is true if the Presentation is genuine;
	 *         the returned value is false if the Presentation is not genuine.
	 * @throws DIDResolveException get the lastest document from chain failed.
	 * @throws DIDBackendException get content from net failed.
	 */
	public boolean isGenuine()
			throws DIDResolveException, DIDBackendException {
		DID signer = getSigner();
		DIDDocument signerDoc = signer.resolve();
		if (signerDoc == null)
			return false;

		// Check the integrity of signer' document.
		if (!signerDoc.isGenuine())
			return false;

		// Unsupported public key type;
		if (!proof.getType().equals(DEFAULT_PUBLICKEY_TYPE))
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

		String json = toJson(true);
		return signerDoc.verify(proof.getVerificationMethod(),
				proof.getSignature(), json.getBytes(),
				proof.getRealm().getBytes(), proof.getNonce().getBytes());
	}

	/**
	 * Check whether the Presentation is genuine or not with asynchronous mode.
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
	 * Check whether the Presentation is valid or not.
	 *
	 * @return the returned value is true if the Presentation is valid;
	 *         the returned value is false if the Presentation is not valid.
	 * @throws DIDResolveException get the lastest document from chain failed.
	 * @throws DIDBackendException get content from net failed.
	 */
	public boolean isValid() throws DIDResolveException, DIDBackendException {
		DID signer = getSigner();
		DIDDocument signerDoc = signer.resolve();

		// Check the validity of signer' document.
		if (!signerDoc.isValid())
			return false;

		// Unsupported public key type;
		if (!proof.getType().equals(DEFAULT_PUBLICKEY_TYPE))
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

		String json = toJson(true);
		return signerDoc.verify(proof.getVerificationMethod(),
				proof.getSignature(), json.getBytes(),
				proof.getRealm().getBytes(), proof.getNonce().getBytes());
	}

	/**
	 * Check whether the Presentation is valid or not with asynchronous mode.
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
	 * Get Presentation Proof object.
	 *
	 * @return the Presentation Proof object
	 */
	public Proof getProof() {
		return proof;
	}

	/**
	 * Set Presentation Proof object.
	 *
	 * @param proof the Presentation Proof object.
	 */
	protected void setProof(Proof proof) {
		this.proof = proof;
	}

	private void parse(Reader reader) throws MalformedPresentationException {
		ObjectMapper mapper = new ObjectMapper();
		try {
			JsonNode node = mapper.readTree(reader);
			parse(node);
		} catch (IOException e) {
			throw new MalformedPresentationException("Parse presentation error.", e);
		}
	}

	private void parse(InputStream in) throws MalformedPresentationException {
		ObjectMapper mapper = new ObjectMapper();
		try {
			JsonNode node = mapper.readTree(in);
			parse(node);
		} catch (IOException e) {
			throw new MalformedPresentationException("Parse presentation error.", e);
		}
	}

	private void parse(String json) throws MalformedPresentationException {
		ObjectMapper mapper = new ObjectMapper();
		try {
			JsonNode node = mapper.readTree(json);
			parse(node);
		} catch (IOException e) {
			throw new MalformedPresentationException("Parse presentation error.", e);
		}
	}

	private void parse(JsonNode presentation) throws MalformedPresentationException {
		Class<MalformedPresentationException> clazz = MalformedPresentationException.class;

		String type = JsonHelper.getString(presentation, TYPE,
				false, null, "presentation type", clazz);
		if (!type.contentEquals(DEFAULT_PRESENTATION_TYPE))
			throw new MalformedPresentationException("Unknown presentation type: " + type);
		else
			setType(type);

		Date created = JsonHelper.getDate(presentation, CREATED,
				false, null, "presentation created date", clazz);
		setCreated(created);

		JsonNode node = presentation.get(VERIFIABLE_CREDENTIAL);
		if (node == null)
			throw new MalformedPresentationException("Missing credentials.");
		parseCredential(node);

		node = presentation.get(PROOF);
		if (node == null)
			throw new MalformedPresentationException("Missing credentials.");
		Proof proof = Proof.fromJson(node, null);
		setProof(proof);
	}

	private void parseCredential(JsonNode node)
			throws MalformedPresentationException {
		if (!node.isArray())
			throw new MalformedPresentationException(
					"Invalid verifiableCredentia, should be an array.");

		if (node.size() == 0)
			throw new MalformedPresentationException(
					"Invalid verifiableCredentia, should not be an empty array.");

		for (int i = 0; i < node.size(); i++) {
			try {
				VerifiableCredential vc = VerifiableCredential.fromJson(node.get(i));
				addCredential(vc);
			} catch (MalformedCredentialException e) {
				throw new MalformedPresentationException(e.getMessage(), e);
			}
		}
	}

	/**
	 * Get Presentation from input content.
	 *
	 * @param reader the Reader content
	 * @return the Presentation object
	 * @throws MalformedCredentialException the Presentation is malfromed.
	 */
	public static VerifiablePresentation fromJson(Reader reader)
			throws MalformedPresentationException {
		if (reader == null)
			throw new IllegalArgumentException();

		VerifiablePresentation vp = new VerifiablePresentation();
		vp.parse(reader);

		return vp;
	}

	/**
	 * Get Presentation from input content.
	 *
	 * @param in the InputStream content
	 * @return the Presentation object
	 * @throws MalformedCredentialException the Presentation is malfromed.
	 */
	public static VerifiablePresentation fromJson(InputStream in)
			throws MalformedPresentationException {
		if (in == null)
			throw new IllegalArgumentException();

		VerifiablePresentation vp = new VerifiablePresentation();
		vp.parse(in);

		return vp;
	}

	/**
	 * Get Presentation from input content.
	 *
	 * @param json the json string content
	 * @return the Presentation object
	 * @throws MalformedCredentialException the Presentation is malfromed.
	 */
	public static VerifiablePresentation fromJson(String json)
			throws MalformedPresentationException {
		if (json == null || json.isEmpty())
			throw new IllegalArgumentException();

		VerifiablePresentation vp = new VerifiablePresentation();
		vp.parse(json);

		return vp;
	}

	/**
	 * Get json content of Presentation.
	 *
	 * Normalized serialization order:
	 * - type
	 * - created
	 * - verifiableCredential (ordered by name(case insensitive/ascending)
	 * + proof
	 *   - type
	 *   - verificationMethod
	 *   - realm
	 *   - nonce
	 *   - signature
	 *
	 * @param generator the JsonGenerator handle
	 * @param forSign = true, only generate json string without proof;
	 *        forSign = false, getnerate json string the whole Presentation.
	 * @throws IOException  write field to json string failed.
	 */
	protected void toJson(JsonGenerator generator, boolean forSign)
			throws IOException {
		generator.writeStartObject();

		// type
		generator.writeFieldName(TYPE);
		generator.writeString(type);

		// created
		generator.writeFieldName(CREATED);
		generator.writeString(JsonHelper.formatDate(created));

		// credentials
		generator.writeFieldName(VERIFIABLE_CREDENTIAL);
		generator.writeStartArray();
		for (VerifiableCredential vc : credentials.values())
			vc.toJson(generator, null, true);
		generator.writeEndArray();

		// proof
		if (!forSign ) {
			generator.writeFieldName(PROOF);
			proof.toJson(generator);
		}

		generator.writeEndObject();
	}

	/**
	 * Get json content of Presentation.
	 *
	 * @param out the Writer handle
	 * @param forSign = true, only generate json string without proof;
	 *        forSign = false, getnerate json string the whole Presentation.
	 * @throws IOException write field to json string failed.
	 */
	protected void toJson(Writer out, boolean forSign) throws IOException {
		JsonFactory factory = new JsonFactory();
		JsonGenerator generator = factory.createGenerator(out);
		toJson(generator, forSign);
		generator.close();
	}

	/**
	 * Get json content of Presentation.
	 *
	 * @param out the Writer handle
	 * @throws IOException write field to json string failed.
	 */
	public void toJson(Writer out) throws IOException {
		if (out == null)
			throw new IllegalArgumentException();

		toJson(out, false);
	}

	/**
	 * Get json content of Presentation.
	 *
	 * @param out the OutputStream handle
	 * @param charsetName encode using this charset
	 * @throws IOException write field to json string failed.
	 */
	public void toJson(OutputStream out, String charsetName)
			throws IOException {
		if (out == null)
			throw new IllegalArgumentException();

		if (charsetName == null)
			charsetName = "UTF-8";

		toJson(new OutputStreamWriter(out, charsetName));
	}

	/**
	 * Get json content of Presentation.
	 *
	 * @param out the OutputStream handle
	 * @throws IOException write field to json string failed.
	 */
	public void toJson(OutputStream out) throws IOException {
		if (out == null)
			throw new IllegalArgumentException();

		toJson(new OutputStreamWriter(out));
	}

	/**
	 * Get json content of Presentation.
	 *
	 * @param forSign = true, only generate json string without proof;
	 *        forSign = false, getnerate json string the whole Presentation.
	 * @throws IOException write field to json string failed.
	 */
	protected String toJson(boolean forSign) {
		Writer out = new StringWriter(4096);

		try {
			toJson(out, forSign);
		} catch (IOException ignore) {
		}

		return out.toString();
	}

	@Override
	public String toString() {
		return toJson(false);
	}

	/**
	 * Get Presential Builder.
	 *
	 * @param did the owner of Presentation.
	 * @param signKey the key to sign
	 * @param store the specified DIDStore
	 * @return the Presential Builder object
	 * @throws DIDStoreException can not load DID.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public static Builder createFor(DID did, DIDURL signKey, DIDStore store)
			throws DIDStoreException, InvalidKeyException {
		if (did == null || store == null)
			throw new IllegalArgumentException();

		DIDDocument signer = store.loadDid(did);
		if (signer == null)
			throw new DIDStoreException("Can not load DID.");

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
	 * Get Presential Builder.
	 *
	 * @param did the owner of Presentation.
	 * @param store the specified DIDStore
	 * @return the Presential Builder object
	 * @throws DIDStoreException can not load DID.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public static Builder createFor(DID did, DIDStore store)
			throws DIDStoreException, InvalidKeyException {
		return createFor(did, null, store);
	}

	public static class Builder {
		private DIDDocument signer;
		private DIDURL signKey;
		private String realm;
		private String nonce;
		private VerifiablePresentation presentation;

		/**
		 * Constructs the Presentation Builder with the given value.
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
		 * @param credentials the Credentail array
		 * @return the Presentation Builder object
		 */
		public Builder credentials(VerifiableCredential ... credentials) {
			if (presentation == null)
				throw new IllegalStateException("Presentation already sealed.");

			for (VerifiableCredential vc : credentials) {
				if (!vc.getSubject().getId().equals(signer.getSubject()))
					throw new IllegalArgumentException("Credential '" +
							vc.getId() + "' not match with requested did");

				// TODO: integrity check?
				// if (!vc.isValid())
				//	throw new IllegalArgumentException("Credential '" +
				//			vc.getId() + "' is invalid");

				presentation.addCredential(vc);
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
		 * Finish the Presentation editting.
		 *
		 * @param storepass the password for DIDStore
		 * @return the Presentation object
		 * @throws DIDStoreException there is no an authentication key to sign.
		 */
		public VerifiablePresentation seal(String storepass)
				throws DIDStoreException {
			if (presentation == null)
				throw new IllegalStateException("Presentation already sealed.");

			if (storepass == null || storepass.isEmpty())
				throw new IllegalArgumentException();

			String json = presentation.toJson(true);
			String sig = signer.sign(signKey, storepass, json.getBytes(),
					realm.getBytes(), nonce.getBytes());

			Proof proof = new Proof(signKey, realm, nonce, sig);
			presentation.setProof(proof);

			// Invalidate builder
			VerifiablePresentation vp = presentation;
			this.presentation = null;

			return vp;
		}
	}
}
