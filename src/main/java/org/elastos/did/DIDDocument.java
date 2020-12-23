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
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Function;

import org.elastos.did.crypto.Base58;
import org.elastos.did.crypto.Base64;
import org.elastos.did.crypto.EcdsaSigner;
import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.AlreadySignedException;
import org.elastos.did.exception.DIDBackendException;
import org.elastos.did.exception.DIDDeactivatedException;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDExpiredException;
import org.elastos.did.exception.DIDInvalidException;
import org.elastos.did.exception.DIDNotFoundException;
import org.elastos.did.exception.DIDNotGenuineException;
import org.elastos.did.exception.DIDNotUpToDateException;
import org.elastos.did.exception.DIDObjectAlreadyExistException;
import org.elastos.did.exception.DIDObjectNotExistException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.MalformedCredentialException;
import org.elastos.did.exception.MalformedDIDException;
import org.elastos.did.exception.MalformedDocumentException;
import org.elastos.did.exception.NotControllerException;
import org.elastos.did.jwt.JwtBuilder;
import org.elastos.did.jwt.JwtParserBuilder;
import org.elastos.did.jwt.KeyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.digests.SHA256Digest;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

/**
 * The DIDDocument represents the DID information.
 *
 * This is the concrete serialization of the data model, according to a
 * particular syntax.
 *
 * DIDDocument is a set of data that describes the subject of a DID, including
 * public key, authentication(optional), authorization(optional), credential and
 * services. One document must be have one subject, and at least one public
 * key.
 */
@JsonPropertyOrder({ DIDDocument.ID,
    DIDDocument.CONTROLLER,
    DIDDocument.MULTI_SIGNATURE,
    DIDDocument.PUBLICKEY,
    DIDDocument.AUTHENTICATION,
    DIDDocument.AUTHORIZATION,
    DIDDocument.VERIFIABLE_CREDENTIAL,
    DIDDocument.SERVICE,
    DIDDocument.EXPIRES,
    DIDDocument.PROOF })
public class DIDDocument extends DIDObject<DIDDocument> {
	protected final static String ID = "id";
	protected final static String PUBLICKEY = "publicKey";
	protected final static String TYPE = "type";
	protected final static String CONTROLLER = "controller";
	protected static final String MULTI_SIGNATURE = "multisig";
	protected final static String PUBLICKEY_BASE58 = "publicKeyBase58";
	protected final static String AUTHENTICATION = "authentication";
	protected final static String AUTHORIZATION = "authorization";
	protected final static String SERVICE = "service";
	protected final static String VERIFIABLE_CREDENTIAL = "verifiableCredential";
	protected final static String SERVICE_ENDPOINT = "serviceEndpoint";
	protected final static String EXPIRES = "expires";
	protected final static String PROOF = "proof";
	protected final static String CREATOR = "creator";
	protected final static String CREATED = "created";
	protected final static String SIGNATURE_VALUE = "signatureValue";

	@JsonProperty(ID)
	private DID subject;

	@JsonProperty(CONTROLLER)
	@JsonFormat(with = {JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY,
	                    JsonFormat.Feature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED} )
	@JsonInclude(Include.NON_NULL)
	private List<DID> controllers;
	private Map<DID, DIDDocument> controllerDocs;
	private DID effectiveController;

	@JsonProperty(MULTI_SIGNATURE)
	@JsonInclude(Include.NON_NULL)
	MultiSignature multisig;

	private Map<DIDURL, PublicKey> publicKeys;
	public PublicKey defaultPublicKey;

	@JsonProperty(PUBLICKEY)
	@JsonInclude(Include.NON_NULL)
	private List<PublicKey> _publickeys;
	@JsonProperty(AUTHENTICATION)
	@JsonInclude(Include.NON_NULL)
	private List<WeakPublicKey> _authentications;
	@JsonProperty(AUTHORIZATION)
	@JsonInclude(Include.NON_NULL)
	private List<WeakPublicKey> _authorizations;

	private Map<DIDURL, VerifiableCredential> credentials;
	@JsonProperty(VERIFIABLE_CREDENTIAL)
	@JsonInclude(Include.NON_NULL)
	private List<VerifiableCredential> _credentials;

	private Map<DIDURL, Service> services;
	@JsonProperty(SERVICE)
	@JsonInclude(Include.NON_NULL)
	private List<Service> _services;

	@JsonProperty(EXPIRES)
	@JsonInclude(Include.NON_NULL)
	private Date expires;

	private HashMap<DIDURL, Proof> proofs;
	@JsonProperty(PROOF)
	@JsonInclude(Include.NON_NULL)
	@JsonFormat(with = {JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY,
			JsonFormat.Feature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
	private List<Proof> _proofs;

	private DIDMetadata metadata;

	private static final Logger log = LoggerFactory.getLogger(DIDDocument.class);

	public static class MultiSignature {
		private int m;
		private int n;

		public MultiSignature(int m, int n) {
			apply(m, n);
		}

		private MultiSignature(MultiSignature ms) {
			apply(ms.m, ms.n);
		}

		@JsonCreator
		public MultiSignature(String mOfN) {
			if (mOfN == null || mOfN.isEmpty())
				throw new IllegalArgumentException("Invalid multisig spec");

			String[] mn = mOfN.split(":");
			if (mn == null || mn.length != 2)
				throw new IllegalArgumentException("Invalid multisig spec");

			apply(Integer.valueOf(mn[0]), Integer.valueOf(mn[1]));
		}

		protected void apply(int m, int n) {
			if (m <= 0 || n <= 1 || m > n)
				throw new IllegalArgumentException("Invalid multisig spec");

			this.m = m;
			this.n = n;
		}

		public int m() {
			return m;
		}

		public int n() {
			return n;
		}

		@Override
		@JsonValue
		public String toString() {
			return String.format("%d:%d", m, n);
		}
	}

	/**
     * Publickey is used for digital signatures, encryption and
     * other cryptographic operations, which are the basis for purposes such as
     * authentication or establishing secure communication with service endpoints.
	 */
	@JsonPropertyOrder({ ID, TYPE, CONTROLLER, PUBLICKEY_BASE58 })
	public static class PublicKey implements DIDEntry {
		@JsonProperty(ID)
		private DIDURL id;
		@JsonProperty(TYPE)
		private String type;
		@JsonProperty(CONTROLLER)
		private DID controller;
		@JsonProperty(PUBLICKEY_BASE58)
		private String keyBase58;
		private boolean authenticationKey;
		private boolean authorizationKey;

		/**
		 * Constructs Publickey with the given value.
		 *
		 * @param id the Id for PublicKey
		 * @param type the type string of PublicKey, default type is "ECDSAsecp256r1"
		 * @param controller the DID who holds private key
		 * @param keyBase58 the string from encoded base58 of public key
		 */
		@JsonCreator
		protected PublicKey(@JsonProperty(value = ID, required = true) DIDURL id,
				@JsonProperty(value = TYPE) String type,
				@JsonProperty(value = CONTROLLER) DID controller,
				@JsonProperty(value = PUBLICKEY_BASE58, required = true) String keyBase58) {
			this.id = id;
			this.type = type != null ? type : Constants.DEFAULT_PUBLICKEY_TYPE;
			this.controller = controller;
			this.keyBase58 = keyBase58;
		}

		/**
		 * Constructs Publickey with the given value(default type is "ECDSAsecp256r1".
		 *
		 * @param id the Id for PublicKey
		 * @param controller the DID who holds private key
		 * @param keyBase58 the string from encoded base58 of public key
		 */
		protected PublicKey(DIDURL id, DID controller, String keyBase58) {
			this(id, null, controller, keyBase58);
		}

		/**
		 * Get the PublicKey id.
		 *
		 * @return the identifier
		 */
		@Override
		public DIDURL getId() {
			return id;
		}

		/**
		 * Get the PublicKey type.
		 *
		 * @return the type string
		 */
		@Override
		public String getType() {
			return type;
		}

		/**
		 * Get the controller of Publickey.
		 *
		 * @return the controller
		 */
		public DID getController() {
			return controller;
		}

		/**
		 * Get public key base58 string.
		 *
		 * @return the key base58 string
		 */
		public String getPublicKeyBase58() {
			return keyBase58;
		}

		/**
		 * Get public key bytes.
		 *
		 * @return the key bytes
		 */
		public byte[] getPublicKeyBytes() {
			return Base58.decode(keyBase58);
		}

		/**
		 * Check if the key is an authentication key or not.
		 *
		 * @return if the key is an authentication key or not
		 */
		public boolean isAuthenticationKey() {
			return authenticationKey;
		}

		private void setAuthenticationKey(boolean authenticationKey) {
			this.authenticationKey = authenticationKey;
		}

		/**
		 * Check if the key is an authorization key or not.
		 *
		 * @return if the key is an authorization key or not
		 */
		public boolean isAuthorizationKey() {
			return authorizationKey;
		}

		private void setAuthorizationKey(boolean authorizationKey) {
			this.authorizationKey = authorizationKey;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;

			if (obj instanceof PublicKey) {
				PublicKey ref = (PublicKey)obj;

				if (getId().equals(ref.getId()) &&
						getType().equals(ref.getType()) &&
						getController().equals(ref.getController()) &&
						getPublicKeyBase58().equals(ref.getPublicKeyBase58()))
					return true;
			}

			return false;
		}
	}

	@JsonSerialize(using = WeakPublicKey.Serializer.class)
	@JsonDeserialize(using = WeakPublicKey.Deserializer.class)
	protected static class WeakPublicKey {
		private DIDURL id;
		private PublicKey key;

		protected WeakPublicKey(DIDURL id) {
			this.id = id;
		}

		protected WeakPublicKey(PublicKey key) {
			this.key = key;
		}

		public boolean isReference() {
			return id != null;
		}

		public DIDURL getId() {
			return id;
		}

		public PublicKey getPublicKey() {
			return key;
		}

		protected void weaken() {
			if (key != null) {
				this.id = key.getId();
				this.key = null;
			}
		}

		static class Serializer extends StdSerializer<WeakPublicKey> {
			private static final long serialVersionUID = -6934608221544406405L;

			public Serializer() {
		        this(null);
		    }

		    public Serializer(Class<WeakPublicKey> t) {
		        super(t);
		    }

			@Override
			public void serialize(WeakPublicKey wpk, JsonGenerator gen,
					SerializerProvider provider) throws IOException {
				if (wpk.isReference())
					gen.writeObject(wpk.getId());
				else
					gen.writeObject(wpk.getPublicKey());
			}
		}

		static class Deserializer extends StdDeserializer<WeakPublicKey> {
			private static final long serialVersionUID = -4252894239212420927L;

			public Deserializer() {
		        this(null);
		    }

		    public Deserializer(Class<?> t) {
		        super(t);
		    }

			@Override
			public WeakPublicKey deserialize(JsonParser p, DeserializationContext ctxt)
					throws IOException, JsonProcessingException {
		    	JsonToken token = p.getCurrentToken();
		    	if (token.equals(JsonToken.VALUE_STRING)) {
		    		DIDURL id = p.readValueAs(DIDURL.class);
		    		return new WeakPublicKey(id);
		    	} else if (token.equals(JsonToken.START_OBJECT)) {
		    		PublicKey key = p.readValueAs(PublicKey.class);
		    		return new WeakPublicKey(key);
		    	} else
		    		throw ctxt.weirdStringException(p.getText(),
		    				PublicKey.class, "Invalid public key");
			}

		}
	}

	/**
     * A Service may represent any type of service the subject
     * wishes to advertise, including decentralized identity management services
     * for further discovery, authentication, authorization, or interaction.
	 */
	@JsonPropertyOrder({ ID, TYPE, SERVICE_ENDPOINT })
	public static class Service implements DIDEntry {
		@JsonProperty(ID)
		private DIDURL id;
		@JsonProperty(TYPE)
		private String type;
		@JsonProperty(SERVICE_ENDPOINT)
		private String endpoint;

		/**
		 * Constructs Service with the given value.
		 *
		 * @param id the id for Service
		 * @param type the type of Service
		 * @param endpoint the address of service point
		 */
		@JsonCreator
		protected Service(@JsonProperty(value = ID, required = true) DIDURL id,
				@JsonProperty(value = TYPE, required = true) String type,
				@JsonProperty(value = SERVICE_ENDPOINT, required = true) String endpoint) {
			this.id = id;
			this.type = type;
			this.endpoint = endpoint;
		}

		/**
		 * Get the service id.
		 *
		 * @return the identifier
		 */
		@Override
		public DIDURL getId() {
			return id;
		}

		/**
		 * Get the service type.
		 *
		 * @return the type string
		 */
		@Override
		public String getType() {
			return type;
		}

		/**
		 * Get service point string.
		 *
		 * @return the service point string
		 */
		public String getServiceEndpoint() {
			return endpoint;
		}
	}

	/**
	 * The Proof represents the proof content of DID Document.
	 */
	@JsonPropertyOrder({ TYPE, CREATED, CREATOR, SIGNATURE_VALUE })
	public static class Proof implements Comparable<Proof>{
		@JsonProperty(TYPE)
		private String type;
		@JsonInclude(Include.NON_NULL)
		@JsonProperty(CREATED)
		private Date created;
		@JsonInclude(Include.NON_NULL)
		@JsonProperty(CREATOR)
		private DIDURL creator;
		@JsonProperty(SIGNATURE_VALUE)
		private String signature;

		/**
		 * Constructs the proof of DIDDocument with the given value.
		 *
		 * @param type the type of Proof
		 * @param created the time to create DIDDocument
		 * @param creator the key to sign
		 * @param signature the signature string
		 */
		@JsonCreator
		protected Proof(@JsonProperty(value = TYPE) String type,
				@JsonProperty(value = CREATED, required = true) Date created,
				@JsonProperty(value = CREATOR) DIDURL creator,
				@JsonProperty(value = SIGNATURE_VALUE, required = true) String signature) {
			this.type = type != null ? type : Constants.DEFAULT_PUBLICKEY_TYPE;
			this.created = created;
			this.creator = creator;
			this.signature = signature;
		}

		/**
		 * Constructs the proof of DIDDocument with the key id and signature string.
		 *
		 * @param creator the key to sign
		 * @param signature the signature string
		 */
		protected Proof(DIDURL creator, String signature) {
			this(null, Calendar.getInstance(Constants.UTC).getTime(), creator, signature);
		}

		/**
		 * Get Proof type.
		 *
		 * @return the type string
		 */
	    public String getType() {
	    	return type;
	    }

	    /**
	     * Get the time to create DIDDocument.
	     *
	     * @return the time
	     */
	    public Date getCreated() {
	    	return created;
	    }

	    /**
	     * Get the key id to sign.
	     *
	     * @return the key id
	     */
	    public DIDURL getCreator() {
	    	return creator;
	    }

	    /**
	     * Get signature string.
	     *
	     * @return the signature string
	     */
	    public String getSignature() {
	    	return signature;
	    }

		@Override
		public int compareTo(Proof proof) {
			int rc = (int)(this.created.getTime() - proof.created.getTime());
			if (rc == 0)
				rc = this.creator.compareTo(proof.creator);
			return rc;
		}
	}

	/**
	 * Set the DIDDocument subject.
	 *
	 * @param subject the owner of DIDDocument
	 */
	@JsonCreator
	protected DIDDocument(@JsonProperty(value = ID, required = true) DID subject) {
		this.subject = subject;
	}

	protected DIDDocument(DID subject, DIDDocument controllerDoc) {
		this.subject = subject;
		this.controllers = new ArrayList<DID>();
		this.controllerDocs = new HashMap<DID, DIDDocument>();

		this.controllers.add(controllerDoc.getSubject());
		this.controllerDocs.put(controllerDoc.getSubject(), controllerDoc);
	}

	/**
	 * Copy constructor.
	 *
	 * @param doc the document be copied
	 */
	protected DIDDocument(DIDDocument doc) {
		this.subject = doc.subject;
		this.controllers = doc.controllers;
		this.controllerDocs = doc.controllerDocs;
		this.multisig = doc.multisig;
		this.publicKeys = doc.publicKeys;
		this._publickeys = doc._publickeys;
		this._authentications = doc._authentications;
		this._authorizations = doc._authorizations;
		this.defaultPublicKey = doc.defaultPublicKey;
		this.credentials = doc.credentials;
		this._credentials = doc._credentials;
		this.services = doc.services;
		this._services = doc._services;
		this.expires = doc.expires;
		this.proofs = doc.proofs;
		this.metadata = doc.metadata;
	}

	private <K, V extends DIDEntry> int getEntryCount(Map<K, V> entries,
			Function<DIDEntry, Boolean> filter) {
		if (entries == null || entries.isEmpty())
			return 0;

		if (filter == null) {
			return entries.size();
		} else {
			int count = 0;
			for (V entry : entries.values()) {
				if (filter.apply(entry))
					count++;
			}

			return count;
		}
	}

	private <K, V extends DIDEntry> int getEntryCount(Map<K, V> entries) {
		return getEntryCount(entries, null);
	}

	private <K, V extends DIDEntry> List<V> getEntries(Map<K, V> entries,
			Function<DIDEntry, Boolean> filter) {
		List<V> lst = new ArrayList<V>(entries == null ? 0 : entries.size());

		if (entries != null && !entries.isEmpty()) {
			if (filter == null) {
				lst.addAll(entries.values());
			} else {
				for (V entry : entries.values()) {
					if (filter.apply(entry))
						lst.add(entry);
				}
			}
		}

		return lst;
	}

	private <K, V extends DIDEntry> List<V> getEntries(Map<K, V> entries) {
		return getEntries(entries, null);
	}

	private <K, V extends DIDEntry> V getEntry(Map<K, V> entries, K id) {
		if (entries == null || entries.isEmpty())
			return null;

		return entries.get(id);
	}

	private <K, V extends DIDEntry> V removeEntry(Map<K, V> entries, K id) {
		if (entries == null || entries.isEmpty() || !entries.containsKey(id))
			throw new DIDObjectNotExistException(id.toString() + " not exists.");

		return entries.remove(id);
	}

	/**
	 * Get subject of DIDDocument.
	 *
	 * @return the DID object
	 */
	public DID getSubject() {
		return subject;
	}

	public boolean isCustomizedDid() {
		return defaultPublicKey == null;
	}

	/**
	 * Get contoller's DID.
	 *
	 * @return the Controllers DID list or empty list if no controller
	 */
	public List<DID> getControllers() {
		List<DID> ctrls = new ArrayList<DID>();
		if (controllers != null)
			ctrls.addAll(controllers);

		return ctrls;
	}

	/**
	 * Get controller count.
	 *
	 * @return the controller count
	 */
	public int getControllerCount() {
		return controllers == null ? 0 : controllers.size();
	}

	/**
	 * Get contoller's DID.
	 *
	 * @return the Controller's DID if only has one controller, other wise null
	 */
	protected DID getController() {
		return (controllers != null && controllers.size() == 1) ? controllers.get(0) : null;
	}

	/**
	 * Check if current DID has controller.
	 *
	 * @return true if has, otherwise false
	 */
	public boolean hasController() {
		return controllers != null && !controllers.isEmpty();
	}

	/**
	 * Check if current DID has specific controller.
	 *
	 * @return true if has, otherwise false
	 */
	public boolean hasController(DID did) {
		return controllers != null && controllers.contains(did);
	}

	/**
	 * Get controller's DID document.
	 *
	 * @return the DIDDocument object or null if no controller
	 */
	protected DIDDocument getControllerDocument(DID did) {
		return controllerDocs.get(did);
	}

	public DID getEffectiveController() {
		return effectiveController;
	}

	protected DIDDocument getEffectiveControllerDocument() {
		return effectiveController == null ? null : getControllerDocument(effectiveController);
	}

	public void setEffectiveController(DID controller) throws NotControllerException {
		if (!isCustomizedDid())
			throw new UnsupportedOperationException("Not customized DID");

		if (!hasController(controller))
			throw new NotControllerException("No this controller");

		effectiveController = controller;

		// attach to the store if necessary
		DIDDocument doc = getControllerDocument(effectiveController);
		if (!doc.getMetadata().attachedStore())
			doc.getMetadata().setStore(getMetadata().getStore());
	}

	public boolean isMultiSignature() {
		return multisig != null;
	}

	public MultiSignature getMultiSignature() {
		return multisig;
	}

	/**
	 * Get the count of public keys.
	 *
	 * @return the count
	 */
	public int getPublicKeyCount() {
		int count = getEntryCount(publicKeys);

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values())
				count += doc.getPublicKeyCount();
		}

		return count;
	}

	/**
	 * Get the public keys array.
	 *
	 * @return the PublicKey array
	 */
	public List<PublicKey> getPublicKeys() {
		List<PublicKey> pks =  getEntries(publicKeys);

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values())
				pks.addAll(doc.getPublicKeys());
		}

		return pks;
	}

	/**
	 * Select public keys with the specified key id or key type.
	 *
	 * @param id the key id
	 * @param type the type string
	 * @return the matched PublicKey array
	 */
	public List<PublicKey> selectPublicKeys(DIDURL id, String type) {
		if (id == null && type == null)
			throw new IllegalArgumentException();

		List<PublicKey> pks = getEntries(publicKeys, (v) -> {
			if (id != null && !v.getId().equals(id))
				return false;

			if (type != null && !v.getType().equals(type))
				return false;

			return true;
		});

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values())
				pks.addAll(doc.selectPublicKeys(id, type));
		}

		return pks;

	}

	/**
	 * Select public keys with the specified key id or key type.
	 *
	 * @param id the key id string
	 * @param type the type string
	 * @return the matched PublicKey array
	 */
	public List<PublicKey> selectPublicKeys(String id, String type) {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return selectPublicKeys(_id, type);
	}

	/**
	 * Get public key matched specified key id.
	 *
	 * @param id the key id string
	 * @return the PublicKey object
	 */
	public PublicKey getPublicKey(String id) {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return getPublicKey(_id);
	}

	/**
	 * Get public key matched specified key id.
	 *
	 * @param id the key id
	 * @return the PublicKey object
	 */
	public PublicKey getPublicKey(DIDURL id) {
		if (id == null)
			throw new IllegalArgumentException();

		PublicKey pk = getEntry(publicKeys, id);
		if (pk != null)
			return pk;

		if (hasController()) {
			DIDDocument doc = getControllerDocument(id.getDid());
			if (doc != null)
				pk = doc.getPublicKey(id);
		}

		return pk;
	}

	/**
	 * Check if the specified public key exists.
	 *
	 * @param id the key id
	 * @return the key exists or not
	 */
	public boolean hasPublicKey(DIDURL id) {
		if (id == null)
			throw new IllegalArgumentException();

		return getPublicKey(id) != null;
	}

	/**
	 * Check if the specified public key exists.
	 *
	 * @param id the key id string
	 * @return the key exists or not
	 */
	public boolean hasPublicKey(String id) {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return hasPublicKey(_id);
	}

	/**
	 * Check if the specified private key exists.
	 *
	 * @param id the key id
	 * @return the key exists or not
	 * @throws DIDStoreException there is no store
	 */
	public boolean hasPrivateKey(DIDURL id) throws DIDStoreException {
		if (id == null)
			throw new IllegalArgumentException();

		if (getPublicKey(id) == null)
			return false;

		if (!getMetadata().attachedStore())
			return false;

		return getMetadata().getStore().containsPrivateKey(id.getDid(), id);
	}

	/**
	 * Check if the specified private key exists.
	 *
	 * @param id the key id string
	 * @return the key exists or not
	 * @throws DIDStoreException there is no store
	 */
	public boolean hasPrivateKey(String id) throws DIDStoreException {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return hasPrivateKey(_id);
	}

	/**
	 * Get default key id of did document.
	 *
	 * @return the default key id
	 */
	public DIDURL getDefaultPublicKeyId() {
		PublicKey pk = getDefaultPublicKey();
		return pk != null ? pk.getId() : null;
	}

	/**
	 * Get default key of did document.
	 *
	 * @return the default key
	 */
	public PublicKey getDefaultPublicKey() {
		if (defaultPublicKey != null)
			return defaultPublicKey;

		if (effectiveController != null)
			return getControllerDocument(effectiveController).getDefaultPublicKey();

		return null;
	}

	/**
	 * Get KeyPair object according to the given key id.
	 *
	 * @param id the given key id
	 * @return the KeyPair object
	 * @throws InvalidKeyException there is no the matched key
	 */
	public KeyPair getKeyPair(DIDURL id) throws InvalidKeyException {
		if (id == null)
			throw new IllegalArgumentException();

		if (!hasPublicKey(id))
			throw new InvalidKeyException("Key no exist");

		HDKey key = HDKey.deserialize(HDKey.paddingToExtendedPublicKey(
				getPublicKey(id).getPublicKeyBytes()));

		return key.getJCEKeyPair();
	}

	/**
	 * Derive the index private key.
	 *
	 * @param index the index
	 * @param storepass the password for DIDStore
	 * @return the extended private key format. (the real private key is
	 *         32 bytes long start from position 46)
	 * @throws DIDStoreException there is no DID store to get root private key
	 */
	public String derive(int index, String storepass) throws DIDStoreException {
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkState(getMetadata().attachedStore(), "Not attached with a store");

		HDKey key = HDKey.deserialize(getMetadata().getStore().loadPrivateKey(
				getSubject(), getDefaultPublicKeyId(), storepass));

		return key.derive(index).serializeBase58();
	}

	private String mapToDerivePath(String identifier, int securityCode) {
		byte digest[] = new byte[32];
		SHA256Digest sha256 = new SHA256Digest();
		byte[] in = identifier.getBytes();
		sha256.update(in, 0, in.length);
		sha256.doFinal(digest, 0);

		StringBuffer path = new StringBuffer(128);
		ByteBuffer bb = ByteBuffer.wrap(digest);
		while (bb.hasRemaining()) {
			int idx = bb.getInt();
			if (idx >= 0)
				path.append(idx);
			else
				path.append(idx & 0x7FFFFFFF).append('H');

			path.append('/');
		}

		if (securityCode >= 0)
			path.append(securityCode);
		else
			path.append(securityCode & 0x7FFFFFFF).append('H');

		return path.toString();
	}

	/**
	 * Derive the extended private key according to identifier string and security code.
	 *
	 * @param identifier the identifier string
	 * @param securityCode the security code
	 * @param storepass the password for DID store
	 * @return the extended derived private key
	 * @throws DIDStoreException there is no DID store to get root private key
	 */
	public String derive(String identifier, int securityCode, String storepass)
			throws DIDStoreException {
		if (identifier == null || identifier.isEmpty() ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		if (!getMetadata().attachedStore())
			throw new DIDStoreException("Not attached with a DID store.");

		HDKey key = HDKey.deserialize(getMetadata().getStore().loadPrivateKey(
				getSubject(), getDefaultPublicKeyId(), storepass));

		String path = mapToDerivePath(identifier, securityCode);
		return key.derive(path).serializeBase58();
	}

	/**
	 * Get KeyPair object according to the given key id.
	 *
	 * @param id the key id string
	 * @return the KeyPair object
	 * @throws InvalidKeyException there is no matched key
	 */
	public KeyPair getKeyPair(String id) throws InvalidKeyException {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return getKeyPair(_id);
	}

	private KeyPair getKeyPair(DIDURL id, String storepass)
			throws InvalidKeyException, DIDStoreException {
		if (id == null || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		if (!hasPublicKey(id))
			throw new InvalidKeyException("Key no exist");

		if (!getMetadata().attachedStore())
			throw new DIDStoreException("Not attached with a DID store.");

		if (!getMetadata().getStore().containsPrivateKey(getSubject(), id))
			throw new InvalidKeyException("Don't have private key");

		HDKey key = HDKey.deserialize(getMetadata().getStore().loadPrivateKey(
				getSubject(), id, storepass));
		return key.getJCEKeyPair();
	}

	/**
	 * Get the count of authentication keys.
	 *
	 * @return the count of authentication key array
	 */
	public int getAuthenticationKeyCount() {
		int count = getEntryCount(publicKeys,
				(v) -> ((PublicKey)v).isAuthenticationKey());

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values())
				count += doc.getAuthenticationKeyCount();
		}

		return count;
	}

	/**
	 * Get the authentication key array.
	 *
	 * @return the matched authentication key array
	 */
	public List<PublicKey> getAuthenticationKeys() {
		List<PublicKey> pks = getEntries(publicKeys,
				(v) -> ((PublicKey)v).isAuthenticationKey());

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values())
				pks.addAll(doc.getAuthenticationKeys());
		}

		return pks;
	}

	/**
	 * Select the authentication key matched the key id or the type.
	 *
	 * @param id the key id
	 * @param type the type of key
	 * @return the matched authentication key array
	 */
	public List<PublicKey> selectAuthenticationKeys(DIDURL id, String type) {
		if (id == null && type == null)
			throw new IllegalArgumentException();

		List<PublicKey> pks = getEntries(publicKeys, (v) -> {
			if (!((PublicKey)v).isAuthenticationKey())
				return false;

			if (id != null && !v.getId().equals(id))
				return false;

			if (type != null && !v.getType().equals(type))
				return false;

			return true;
		});

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values())
				pks.addAll(doc.selectAuthenticationKeys(id, type));
		}

		return pks;
	}

	/**
	 * Select authentication key array matched the key id or the type
	 *
	 * @param id the key id string
	 * @param type the type of key
	 * @return the matched authentication key array
	 */
	public List<PublicKey> selectAuthenticationKeys(String id, String type) {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return selectAuthenticationKeys(_id, type);
	}

	/**
	 * Get authentication key with specified key id.
	 *
	 * @param id the key id
	 * @return the matched authentication key object
	 */
	public PublicKey getAuthenticationKey(DIDURL id) {
		if (id == null)
			throw new IllegalArgumentException();

		PublicKey pk = getPublicKey(id);
		if (pk != null && pk.isAuthenticationKey())
			return pk;
		else
			return null;
	}

	/**
	 * Get authentication key with specified key id.
	 *
	 * @param id the key id string
	 * @return the matched authentication key object
	 */
	public PublicKey getAuthenticationKey(String id) {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return getAuthenticationKey(_id);
	}

    /**
     * Judge whether the given key is authentication key or not.
     *
     * @param id the key id
     * @return the returned value is true if the key is an authentication key;
     *         the returned value is false if the key is not an authentication key.
     */
	public boolean isAuthenticationKey(DIDURL id) {
		return getAuthenticationKey(id) != null;
	}

    /**
     * Judge whether the given key is authentication key or not.
     *
     * @param id the key id string
     * @return the returned value is true if the key is an authentication key;
     *         the returned value is false if the key is not an authentication key.
     */
	public boolean isAuthenticationKey(String id) {
		return getAuthenticationKey(id) != null;
	}

	/**
	 * Get the count of authorization key.
	 *
	 * @return the count
	 */
	public int getAuthorizationKeyCount() {
		int count = getEntryCount(publicKeys,
				(v) -> ((PublicKey)v).isAuthorizationKey());

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values())
				count += doc.getAuthorizationKeyCount();
		}

		return count;
	}

	/**
	 * Get the authorization key array.
	 *
	 * @return the  array
	 */
	public List<PublicKey> getAuthorizationKeys() {
		List<PublicKey> pks = getEntries(publicKeys,
				(v) -> ((PublicKey)v).isAuthorizationKey());

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values())
				pks.addAll(doc.getAuthorizationKeys());
		}

		return pks;
	}

	/**
	 * Select the authorization key array matched the key id or the type.
	 *
	 * @param id the key id
	 * @param type the type of key
	 * @return the matched authorization key array
	 */
	public List<PublicKey> selectAuthorizationKeys(DIDURL id, String type) {
		if (id == null && type == null)
			throw new IllegalArgumentException();

		List<PublicKey> pks = getEntries(publicKeys, (v) -> {
			if (!((PublicKey)v).isAuthorizationKey())
				return false;

			if (id != null && !v.getId().equals(id))
				return false;

			if (type != null && !v.getType().equals(type))
				return false;

			return true;
		});

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values())
				pks.addAll(doc.selectAuthorizationKeys(id, type));
		}

		return pks;
	}

	/**
	 * Select the authorization key array matched the key id or the type.
	 *
	 * @param id the key id string
	 * @param type the type of key
	 * @return the matched authorization key array
	 */
	public List<PublicKey> selectAuthorizationKeys(String id, String type) {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return selectAuthorizationKeys(_id, type);
	}

	/**
	 * Get authorization key matched the given key id.
	 *
	 * @param id the key id
	 * @return the authorization key object
	 */
	public PublicKey getAuthorizationKey(DIDURL id) {
		if (id == null)
			throw new IllegalArgumentException();

		PublicKey pk = getPublicKey(id);
		if (pk != null && pk.isAuthorizationKey())
			return pk;
		else
			return null;
	}

	/**
	 * Get authorization key matched the given key id.
	 *
	 * @param id the key id string
	 * @return the authorization key object
	 */
	public PublicKey getAuthorizationKey(String id) {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return getAuthorizationKey(_id);
	}

	/**
	 * Judge whether the public key matched the given key id is an authorization key.
	 *
	 * @param id the key id
	 * @return the returned value is true if the matched key is an authorization key;
	 *         the returned value is false if the matched key is not an authorization key.
	 */
	public boolean isAuthorizationKey(DIDURL id) {
		return getAuthorizationKey(id) != null;
	}

	/**
	 * Judge whether the public key matched the given key id is an authorization key.
	 *
	 * @param id the key id string
	 * @return the returned value is true if the matched key is an authorization key;
	 *         the returned value is false if the matched key is not an authorization key.
	 */
	public boolean isAuthorizationKey(String id) {
		return getAuthorizationKey(id) != null;
	}

	/**
	 * Get the count of Credential array.
	 *
	 * @return the count
	 */
	public int getCredentialCount() {
		return getEntryCount(credentials);
	}

	/**
	 * Get the Credential array.
	 *
	 * @return the Credential array
	 */
	public List<VerifiableCredential> getCredentials() {
		return getEntries(credentials);
	}

	/**
	 * Select the Credential array matched the given credential id or the type.
	 *
	 * @param id the credential id
	 * @param type the type of credential
	 * @return the matched Credential array
	 */
	public List<VerifiableCredential> selectCredentials(DIDURL id, String type) {
		if (id == null && type == null)
			throw new IllegalArgumentException();

		return getEntries(credentials, (v) -> {
			if (id != null && !v.getId().equals(id))
				return false;

			if (type != null) {
				// Credential's type is a list.
				VerifiableCredential vc = (VerifiableCredential)v;
				if (!Arrays.asList(vc.getType()).contains(type))
					return false;
			}

			return true;
		});
	}

	/**
	 * Select the Credential array matched the given credential id or the type.
	 *
	 * @param id the credential id string
	 * @param type the type of credential
	 * @return the matched Credential array
	 */
	public List<VerifiableCredential> selectCredentials(String id, String type) {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return selectCredentials(_id, type);
	}

	/**
	 * Get the Credential matched the given credential id.
	 *
	 * @param id the credential id
	 * @return the matched Credential object
	 */
	public VerifiableCredential getCredential(DIDURL id) {
		if (id == null)
			throw new IllegalArgumentException();

		return getEntry(credentials, id);
	}

	/**
	 * Get the Credential matched the given credential id.
	 *
	 * @param id the credential id string
	 * @return the matched Credential object
	 */
	public VerifiableCredential getCredential(String id) {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return getCredential(_id);
	}

	/**
	 * Get the count of Service array.
	 *
	 * @return the count
	 */
	public int getServiceCount() {
		return getEntryCount(services);
	}

	/**
	 * Get the Service array.
	 *
	 * @return the Service array
	 */
	public List<Service> getServices() {
		return getEntries(services);
	}

	/**
	 * Select Service array matched the given service id or the type.
	 *
	 * @param id the service id
	 * @param type the type of service
	 * @return the matched Service array
	 */
	public List<Service> selectServices(DIDURL id, String type) {
		if (id == null && type == null)
			throw new IllegalArgumentException();

		return getEntries(services, (v) -> {
			if (id != null && !v.getId().equals(id))
				return false;

			if (type != null && !v.getType().equals(type))
				return false;

			return true;
		});
	}

	/**
	 * Select the Service array matched the given service id or the type.
	 *
	 * @param id the service id string
	 * @param type the type of service
	 * @return the matched Service array
	 */
	public List<Service> selectServices(String id, String type) {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return selectServices(_id, type);
	}

	/**
	 * Get the Service matched the given service id.
	 *
	 * @param id the service id
	 * @return the matched Service object
	 */
	public Service getService(DIDURL id) {
		if (id == null)
			throw new IllegalArgumentException();

		return getEntry(services, id);
	}

	/**
	 * Get the Service matched the given service id.
	 *
	 * @param id the service id string
	 * @return the matched Service object
	 */
	public Service getService(String id) {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return getService(_id);
	}

    /**
     * Get expires time of did document.
     *
     * @return the expires time
     */
	public Date getExpires() {
		return expires;
	}

	/**
	 * Get last modified time.
	 *
	 * @return the last modified time
	 */
	public Date getLastModified() {
		return getProof().getCreated();
	}

	/**
	 * Get last modified time.
	 *
	 * @return the last modified time
	 */
	public String getSignature() {
		return getProof().getSignature();
	}

	/**
	 * Get Proof object from did document.
	 *
	 * @return the Proof object
	 */
	protected Proof getProof() {
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

	private void addProof(Proof proof) throws MalformedDocumentException {
		if (proofs == null)
			proofs = new HashMap<DIDURL, Proof>();

		if (proofs.containsKey(proof.getCreator()))
			throw new MalformedDocumentException("Aleady exist proof from " + proof.getCreator());

		proofs.put(proof.getCreator(), proof);
		this._proofs = new ArrayList<Proof>(new TreeSet<Proof>(proofs.values()));
	}


	/**
	 * Get current object's DID context.
	 *
	 * @return the DID object or null
	 */
	@Override
	protected DID getSerializeContextDid() {
		return getSubject();
	}

	/**
	 * Sanitize routine before sealing or after deserialization.
	 *
	 * @param withProof check the proof object or not
	 * @throws MalformedDocumentException if the document object is invalid
	 */
	@Override
	protected void sanitize(boolean withProof) throws MalformedDocumentException {
		if (withProof) {
			sanitizeControllers();
			sanitizePublickKey();
			sanitizeCredential();
			sanitizeService();
		}

		if (controllers != null && !controllers.isEmpty()) {
			if (controllers.size() == 1) {
				if (multisig != null)
					throw new MalformedDocumentException("Invalid multisig property");
			} else {
				if (multisig == null)
					throw new MalformedDocumentException("Missing multisig property");

				if (multisig.n() != controllers.size())
					throw new MalformedDocumentException("Invalid multisig property");
			}

			Collections.sort(controllers);
		}

		if (publicKeys != null && !publicKeys.isEmpty()) {
			this._publickeys = new ArrayList<PublicKey>(publicKeys.values());
			this._authentications = new ArrayList<WeakPublicKey>();
			this._authorizations = new ArrayList<WeakPublicKey>();
			for (PublicKey pk : publicKeys.values()) {
				if (defaultPublicKey == null && pk.getController().equals(getSubject())) {
					String address = HDKey.toAddress(pk.getPublicKeyBytes());
					if (address.equals(getSubject().getMethodSpecificId())) {
						defaultPublicKey = pk;
						pk.setAuthenticationKey(true);
					}
				}

				if (pk.isAuthenticationKey())
					_authentications.add(new WeakPublicKey(pk.getId()));

				if (pk.isAuthorizationKey())
					_authorizations.add(new WeakPublicKey(pk.getId()));
			}

			if (!hasController() && defaultPublicKey == null)
				throw new MalformedDocumentException("Missing default public key.");

			if (_authentications.size() == 0)
				this._authentications = null;

			if (_authorizations.size() == 0)
				this._authorizations = null;
		} else {
			if (controllers == null || controllers.isEmpty())
				throw new MalformedDocumentException("Missing public key.");

			this._publickeys = null;
			this._authentications = null;
			this._authorizations = null;
		}

		if (controllers != null && controllers.size() == 1)
			effectiveController = controllers.get(0);

		if (credentials != null && !credentials.isEmpty())
			this._credentials = new ArrayList<VerifiableCredential>(credentials.values());
		else
			this._credentials = null;

		if (services != null && !services.isEmpty())
			this._services = new ArrayList<Service>(services.values());
		else
			this._services = null;

		if (expires == null)
			throw new MalformedDocumentException("Missing document expires.");

		if (withProof) {
			sanitizeProof();
			this._proofs = new ArrayList<Proof>(new TreeSet<Proof>(proofs.values()));
		}
	}

	private void sanitizeControllers() throws MalformedDocumentException {
		if (controllers == null || controllers.isEmpty())
			return;

		controllerDocs = new HashMap<DID, DIDDocument>();
		try {
			for (DID did : controllers) {
				DIDDocument doc = did.resolve();
				controllerDocs.put(did, doc);
			}
		} catch (DIDResolveException e) {
				throw new  MalformedDocumentException("Can not resolve the controller's DID");
		}
	}

	private void sanitizePublickKey() throws MalformedDocumentException {
		Map<DIDURL, PublicKey> pks = new TreeMap<DIDURL, PublicKey>();

		if (_publickeys != null && _publickeys.size() > 0) {
			for (PublicKey pk : _publickeys) {
				if (pk.getId() == null)
					throw new MalformedDocumentException("Missing public key id.");

				if (pk.getId().getDid() == null)
					pk.getId().setDid(getSubject());

				if (pks.containsKey(pk.getId()))
					throw new MalformedDocumentException("Public key already exists: " + pk.getId());

				if (pk.getPublicKeyBase58() == null || pk.getPublicKeyBase58().isEmpty())
					throw new MalformedDocumentException("Missing public key base58 value.");

				if (pk.getType() == null)
					pk.type = Constants.DEFAULT_PUBLICKEY_TYPE;

				if (pk.getController() == null)
					pk.controller = getSubject();

				pks.put(pk.getId(), pk);
			}
		}

		if (_authentications != null && _authentications.size() > 0) {
			PublicKey pk;

			for (WeakPublicKey wpk : _authentications) {
				if (wpk.isReference()) {
					if (wpk.getId().getDid() == null)
						wpk.getId().setDid(getSubject());

					pk = pks.get(wpk.getId());
					if (pk == null)
						throw new MalformedDocumentException("Public key not exists: " + wpk.getId());
				} else {
					pk = wpk.getPublicKey();

					if (pk.getId().getDid() == null)
						pk.getId().setDid(getSubject());

					if (pks.containsKey(pk.getId()))
						throw new MalformedDocumentException("Public key already exists: " + pk.getId());

					if (pk.getPublicKeyBase58() == null || pk.getPublicKeyBase58().isEmpty())
						throw new MalformedDocumentException("Missing public key base58 value.");

					if (pk.getType() == null)
						pk.type = Constants.DEFAULT_PUBLICKEY_TYPE;

					if (pk.getController() == null)
						pk.controller = getSubject();

					wpk.weaken();
					pks.put(pk.getId(), pk);
				}

				pk.setAuthenticationKey(true);
			}
		}

		if (_authorizations != null && _authorizations.size() > 0) {
			PublicKey pk;

			for (WeakPublicKey wpk : _authorizations) {
				if (wpk.isReference()) {
					if (wpk.getId().getDid() == null)
						wpk.getId().setDid(getSubject());

					pk = pks.get(wpk.getId());
					if (pk == null)
						throw new MalformedDocumentException("Public key not exists: " + wpk.getId());
				} else {
					pk = wpk.getPublicKey();

					if (pk.getId().getDid() == null)
						pk.getId().setDid(getSubject());

					if (pks.containsKey(pk.getId()))
						throw new MalformedDocumentException("Public key already exists: " + pk.getId());

					if (pk.getPublicKeyBase58() == null || pk.getPublicKeyBase58().isEmpty())
						throw new MalformedDocumentException("Missing public key base58 value.");

					if (pk.getType() == null)
						pk.type = Constants.DEFAULT_PUBLICKEY_TYPE;

					if (pk.getController() == null)
						throw new MalformedDocumentException("Public key missing controller: " + pk.getId());
					else {
						if (pk.getController().equals(getSubject()))
							throw new MalformedDocumentException("Authorization key with wrong controller: " + pk.getId());
					}

					wpk.weaken();
					pks.put(pk.getId(), pk);
				}

				pk.setAuthorizationKey(true);
			}
		}

		// for customized DID with controller, could be no public keys
		this.publicKeys = pks.size() > 0 ? pks : null;
	}

	private void sanitizeCredential() throws MalformedDocumentException {
		if (_credentials == null || _credentials.size() == 0)
			return;

		Map<DIDURL, VerifiableCredential> vcs = new TreeMap<DIDURL, VerifiableCredential>();
		for (VerifiableCredential vc : _credentials) {
			if (vc.getId() == null)
				throw new MalformedDocumentException("Missing credential id.");

			if (vc.getId().getDid() == null)
				vc.getId().setDid(getSubject());

			if (vcs.containsKey(vc.getId()))
				throw new MalformedDocumentException("Credential already exists: " + vc.getId());

			if (vc.getSubject().getId() == null)
				vc.getSubject().setId(getSubject());

			try {
				vc.sanitize();
			} catch (DIDSyntaxException e) {
				throw new MalformedDocumentException(e.getMessage(), e);
			}

			vcs.put(vc.getId(), vc);
		}

		this.credentials = vcs;
	}

	private void sanitizeService() throws MalformedDocumentException {
		if (_services == null || _services.size() == 0)
			return;

		Map<DIDURL, Service> svcs = new TreeMap<DIDURL, Service>();
		for (Service svc : _services) {
			if (svc.getId() == null)
				throw new MalformedDocumentException("Missing service id.");

			if (svc.getType() == null || svc.getType().isEmpty())
				throw new MalformedDocumentException("Missing service type.");

			if (svc.getServiceEndpoint() == null || svc.getServiceEndpoint().isEmpty())
				throw new MalformedDocumentException("Missing service endpoint.");

			if (svc.getId().getDid() == null)
				svc.getId().setDid(getSubject());

			if (svcs.containsKey(svc.getId()))
				throw new MalformedDocumentException("Service already exists: " + svc.getId());

			svcs.put(svc.getId(), svc);
		}

		this.services = svcs;
	}

	private void sanitizeProof() throws MalformedDocumentException {
		if (_proofs == null || _proofs.size() == 0)
			throw new MalformedDocumentException("Missing document proof");

		if (multisig == null) {
			if (_proofs.size() != 1)
				throw new MalformedDocumentException("Invalid document proof");

			Proof proof = _proofs.get(0);

			if (proof.getCreator() == null) {
				if (getDefaultPublicKey() == null)
					throw new MalformedDocumentException("No explict creator key");

				proof.creator = getDefaultPublicKeyId();
			} else {
				if (proof.getCreator().getDid() == null)
					proof.getCreator().setDid(getSubject());
			}

			addProof(proof);
		} else {
			for (Proof proof : _proofs) {
				if (proof.getCreator() == null) {
					throw new MalformedDocumentException("Missing creator key");
				} else {
					if (proof.getCreator().getDid() == null)
						throw new MalformedDocumentException("Invalid creator key");
				}

				addProof(proof);
			}
		}
	}

	/**
	 * Set DID Metadata object for did document.
	 *
	 * @param metadata the DIDMetadataImpl object
	 */
	protected void setMetadata(DIDMetadata metadata) {
		this.metadata = metadata;
		subject.setMetadata(metadata);
	}

	/**
	 * Get DID Metadata object from did document.
	 *
	 * @return the DIDMetadata object
	 */
	public DIDMetadata getMetadata() {
		if (metadata == null) {
			metadata = new DIDMetadata();
			subject.setMetadata(metadata);
		}

		return metadata;
	}

	private DIDStore getStore() {
		return metadata == null ? null : metadata.getStore();
	}

	/**
	 * Store DID Metadata.
	 *
	 * @throws DIDStoreException store DID Metadata failed.
	 */
	public void saveMetadata() throws DIDStoreException {
		if (metadata != null && metadata.attachedStore())
			metadata.getStore().storeDidMetadata(getSubject(), metadata);
	}

	/**
	 * Judge whether the did document is expired or not.
	 *
	 * @return the returned value is true if the did document is expired;
	 *         the returned value is false if the did document is not expired.
	 */
	public boolean isExpired() {
		Calendar now = Calendar.getInstance(Constants.UTC);

		Calendar expireDate  = Calendar.getInstance(Constants.UTC);
		expireDate.setTime(expires);

		return now.after(expireDate);
	}

	/**
	 * Judge whether the did document is tampered or not.
	 *
	 * @return the returned value is true if the did document is genuine;
	 *         the returned value is false if the did document is not genuine.
	 */
	public boolean isGenuine() {
		// Proofs count should match with multisig
		if ((getControllerCount() > 1 && proofs.size() != multisig.m()) ||
				(getControllerCount() <= 1 && proofs.size() != 1))
			return false;

		// Document should signed(only) by default public key.
		if (!isCustomizedDid()) {
			Proof proof = getProof();

			// Unsupported public key type;
			if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE))
				return false;

			if (!proof.getCreator().equals(getDefaultPublicKeyId()))
				return false;

			try {
				DIDDocument doc = new DIDDocument(this);
				doc.proofs = null;
				String json = doc.serialize(true);

				if (!verify(proof.getCreator(), proof.getSignature(), json.getBytes()))
					return false;
			} catch (DIDSyntaxException ignore) {
				// Should never happen
				log.error("INTERNAL - Serialize document", ignore);
				return false;
			}

			return true;
		} else {
			List<DID> checkedControllers = new ArrayList<DID>(_proofs.size());

			for (Proof proof : _proofs) {
				// Unsupported public key type;
				if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE))
					return false;

				DIDDocument controllerDoc = getControllerDocument(proof.getCreator().getDid());
				if (controllerDoc == null)
					return false;

				// if already checked this controller
				if (checkedControllers.contains(proof.getCreator().getDid()))
					return false;

				if (!controllerDoc.isGenuine())
					return false;

				if (!proof.getCreator().equals(controllerDoc.getDefaultPublicKeyId()))
					return false;

				try {
					DIDDocument doc = new DIDDocument(this);
					doc.proofs = null;
					String json = doc.serialize(true);

					if (!controllerDoc.verify(proof.getCreator(), proof.getSignature(), json.getBytes()))
						return false;
				} catch (DIDSyntaxException ignore) {
					// Should never happen
					log.error("INTERNAL - Serialize document", ignore);
					return false;
				}
			}

			return true;
		}
	}

	/**
	 * Judge whether the did document is deactivated or not.
	 *
	 * @return the returned value is true if the did document is genuine;
	 *         the returned value is false if the did document is not genuine.
	 */
	public boolean isDeactivated() {
		return getMetadata().isDeactivated();
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

		return _proofs.size() == (multisig == null ? 1 : multisig.m());
	}

	/**
	 * Judge whether the did document is valid or not.
	 *
	 * @return the returned value is true if the did document is valid;
	 *         the returned value is false if the did document is not valid.
	 */
	public boolean isValid() {
		if (isDeactivated() || isExpired() || !isGenuine())
			return false;

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values()) {
				if (doc.isDeactivated() || !doc.isGenuine())
					return false;
			}
		}

		return true;
	}

	protected DIDDocument copy() {
		DIDDocument doc = new DIDDocument(subject);

		doc.controllers = this.controllers != null ? new ArrayList<DID>(controllers) : null;
		doc.controllerDocs = this.controllerDocs != null ? new HashMap<DID, DIDDocument>(controllerDocs) : null;
		doc.multisig = this.multisig != null ? new MultiSignature(this.multisig) : null;
		doc.publicKeys = this.publicKeys != null ? new TreeMap<DIDURL, PublicKey>(publicKeys) : null;
		doc.defaultPublicKey = this.defaultPublicKey;

		if (credentials != null)
			doc.credentials = new TreeMap<DIDURL, VerifiableCredential>(credentials);

		if (services != null)
			doc.services = new TreeMap<DIDURL, Service>(services);

		doc.expires = expires;

		doc.proofs = this.proofs != null ? new HashMap<DIDURL, Proof>(proofs) : null;

		DIDMetadata metadata = getMetadata().clone();
		doc.setMetadata(metadata);

		return doc;
	}

	/**
	 * Get DID Document Builder object.
	 *
	 * @return the Builder object
	 * @throws DIDStoreException
	 */
	public Builder edit() {
		if (getControllerCount() > 1)
			throw new UnsupportedOperationException("Can not determin current identity");

		return new Builder(copy());
	}

	public Builder edit(DIDDocument controller) throws NotControllerException {
		if (!isCustomizedDid())
			throw new UnsupportedOperationException("This method only applies on cutomized DID document");

		if (!hasController(controller.getSubject()))
			throw new NotControllerException("DID no this controller: " + controller.getSubject());

		return new Builder(copy(), controller);
	}

	/**
	 * Sign the data by the specified key.
	 *
	 * @param id the key id
	 * @param storepass the password for DIDStore
	 * @param data the data be signed
	 * @return the signature string
	 * @throws InvalidKeyException if the sign key is invalid
	 * @throws DIDStoreException there is no DIDStore to get private key
	 */
	public String sign(DIDURL id, String storepass, byte[] ... data)
			throws InvalidKeyException, DIDStoreException {
		if (data == null || data.length == 0 || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		byte[] digest = EcdsaSigner.sha256Digest(data);
		return signDigest(id, storepass, digest);
	}

	/**
	 * Sign the data by the specified key.
	 *
	 * @param id the key id string
	 * @param storepass the password for DIDStore
	 * @param data the data be signed
	 * @return the signature string
	 * @throws InvalidKeyException if the sign key is invalid
	 * @throws DIDStoreException there is no DIDStore to get private key.
	 */
	public String sign(String id, String storepass, byte[] ... data)
			throws InvalidKeyException, DIDStoreException {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return sign(_id, storepass, data);
	}

	/**
	 * Sign the data by the default key.
	 *
	 * @param storepass the password for DIDStore
	 * @param data the data be signed
	 * @return the signature string
	 * @throws DIDStoreException there is no DIDStore to get private key.
	 */
	public String sign(String storepass, byte[] ... data)
			throws DIDStoreException {
		try {
			return sign((DIDURL)null, storepass, data);
		} catch (InvalidKeyException ignore) {
			// should never happen
			log.error("INTERNAL - Default key error", ignore);
			return null;
		}
	}

	/**
	 * Sign the digest data by the specified key.
	 *
	 * @param id the key id
	 * @param storepass the password for DIDStore
	 * @param digest the digest data to be signed
	 * @return the signature string
	 * @throws InvalidKeyException if the sign key is invalid
	 * @throws DIDStoreException there is no DIDStore to get private key
	 */
	public String signDigest(DIDURL id, String storepass, byte[] digest)
			throws InvalidKeyException, DIDStoreException {
		if (digest == null || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		if (!getMetadata().attachedStore())
			throw new DIDStoreException("Not attached with a DID store.");

		PublicKey pk = id != null ? getPublicKey(id) : getDefaultPublicKey();
		if (pk == null)
			throw new InvalidKeyException("Invalid sign key");

		DID signer = null;
		if (pk.getController().equals(getSubject()))
			signer = getSubject();
		else if (hasController()) {
			controllers.contains(pk.getController());
			signer = pk.getController();
		} else {
			throw new InvalidKeyException("Invalid sign key");
		}

		return getMetadata().getStore().sign(signer, id, storepass, digest);
	}

	/**
	 * Sign the digest data by the specified key.
	 *
	 * @param id the key id string
	 * @param storepass the password for DIDStore
	 * @param digest the digest data to be signed
	 * @return the signature string
	 * @throws InvalidKeyException if the sign key is invalid
	 * @throws DIDStoreException there is no DIDStore to get private key.
	 */
	public String signDigest(String id, String storepass, byte[] digest)
			throws InvalidKeyException, DIDStoreException {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return signDigest(_id, storepass, digest);
	}

	/**
	 * Sign the digest data by the default key.
	 *
	 * @param storepass the password for DIDStore
	 * @param digest the digest data to be signed
	 * @return the signature string
	 * @throws DIDStoreException there is no DIDStore to get private key.
	 */
	public String signDigest(String storepass, byte[] digest)
			throws DIDStoreException {
		try {
			return signDigest((DIDURL)null, storepass, digest);
		} catch (InvalidKeyException ignore) {
			// should never happen
			log.error("INTERNAL - Default key error", ignore);
			return null;
		}
	}

	/**
	 * Verify the signature string by data and the sign key.
	 *
	 * @param id the key id
	 * @param signature the signature string
	 * @param data the data to be signed
	 * @return the returned value is true if verifing data is successfully;
	 *         the returned value is false if verifing data is not successfully.
	 */
	public boolean verify(DIDURL id, String signature, byte[] ... data) {
		if (signature == null || signature.isEmpty() || data == null || data.length == 0)
			throw new IllegalArgumentException();

		byte[] digest = EcdsaSigner.sha256Digest(data);
		return verifyDigest(id, signature, digest);
	}

	/**
	 * Verify the signature string by data and the sign key.
	 *
	 * @param id the key id string
	 * @param signature the signature string
	 * @param data the data to be signed
	 * @return the returned value is true if verifing data is successfully;
	 *         the returned value is false if verifing data is not successfully.
	 */
	public boolean verify(String id, String signature, byte[] ... data) {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return verify(_id, signature, data);
	}

	/**
	 * Verify the signature string by data and the default key.
	 *
	 * @param signature the signature string
	 * @param data the data to be signed
	 * @return the returned value is true if verifing data is successfully;
	 *         the returned value is false if verifing data is not successfully.
	 */
	public boolean verify(String signature, byte[] ... data) {
		return verify((DIDURL)null, signature, data);
	}

	/**
	 * Verify the digest by the specified key.
	 *
	 * @param id the key id
	 * @param signature the signature string
	 * @param digest the digest data be signed
	 * @return the returned value is true if verifing digest is successfully;
	 *         the returned value is false if verifing digest is not successfully.
	 */
	public boolean verifyDigest(DIDURL id, String signature, byte[] digest) {
		if (signature == null || signature.isEmpty() || digest == null)
			throw new IllegalArgumentException();

		PublicKey pk = id != null ? getPublicKey(id) : getDefaultPublicKey();
		if (pk == null)
			// TODO: checkme
			// throw new InvalidKeyException("Invalid sign key");
			return false;

		byte[] binkey = pk.getPublicKeyBytes();
		byte[] sig = Base64.decode(signature,
				Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);

		return EcdsaSigner.verify(binkey, sig, digest);
	}

	/**
	 * Verify the digest by the specified key.
	 *
	 * @param id the key id string
	 * @param signature the signature string
	 * @param digest the digest data be signed
	 * @return the returned value is true if verifing digest is successfully;
	 *         the returned value is false if verifing digest is not successfully.
	 */
	public boolean verifyDigest(String id, String signature, byte[] digest) {
		DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
		return verifyDigest(_id, signature, digest);
	}

	/**
	 * Verify the digest by the default key.
	 *
	 * @param signature the signature string
	 * @param digest the digest data be signed
	 * @return the returned value is true if verifing digest is successfully;
	 *         the returned value is false if verifing digest is not successfully.
	 */
	public boolean verifyDigest(String signature, byte[] digest) {
		return verifyDigest((DIDURL)null, signature, digest);
	}

	public JwtBuilder jwtBuilder() {
		JwtBuilder builder = new JwtBuilder(getSubject().toString(), new KeyProvider() {

			@Override
			public java.security.PublicKey getPublicKey(String id)
					throws InvalidKeyException {
				DIDURL _id = id == null ? getDefaultPublicKeyId() :
					new DIDURL(getSubject(), id);

				return getKeyPair(_id).getPublic();
			}

			@Override
			public PrivateKey getPrivateKey(String id, String storepass)
					throws InvalidKeyException, DIDStoreException {
				DIDURL _id = id == null ? getDefaultPublicKeyId() :
					new DIDURL(getSubject(), id);

				return getKeyPair(_id, storepass).getPrivate();
			}
		});

		return builder.setIssuer(getSubject().toString());
	}

	public JwtParserBuilder jwtParserBuilder() {
		JwtParserBuilder jpb = new JwtParserBuilder(new KeyProvider() {

			@Override
			public java.security.PublicKey getPublicKey(String id)
					throws InvalidKeyException {
				DIDURL _id = id == null ? getDefaultPublicKeyId() :
					new DIDURL(getSubject(), id);

				return getKeyPair(_id).getPublic();
			}

			@Override
			public PrivateKey getPrivateKey(String id, String storepass) {
				return null;
			}
		});

		jpb.requireIssuer(getSubject().toString());
		return jpb;
	}

	public TransferTicket createTransferTicket(DID did, DID to, String storepass)
			throws DIDResolveException, NotControllerException, DIDStoreException {
		if (did == null || to == null || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		TransferTicket ticket = new TransferTicket(did, to);
		try {
			ticket.seal(this, storepass);
		} catch (AlreadySignedException ignore) {
			// Should never happen
			log.error("INTERNAL - Seal the transfer ticket", ignore);
			return null;
		}

		return ticket;
	}

	public TransferTicket sign(TransferTicket ticket, String storepass)
			throws NotControllerException, AlreadySignedException, DIDStoreException {
		if (ticket == null || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		ticket.seal(this, storepass);
		return ticket;
	}

	public DIDDocument sign(DIDDocument doc, String storepass)
			throws NotControllerException, DIDStoreException {
		if (doc == null || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		if (!doc.isCustomizedDid())
			throw new UnsupportedOperationException("Not a customized DID");

		if (!doc.hasController(getSubject()))
			throw new NotControllerException();

		Builder builder = doc.edit(this);
		try {
			return builder.seal(storepass);
		} catch (MalformedDocumentException ignore) {
			log.error("INTERNAL - sign customized did document", ignore);
			return null;
		}
	}

	/**
	 * Publish DID Document to the ID chain.
	 *
	 * @param signKey the key to sign
	 * @param force force = true, must be publish whether the local document is lastest one or not;
	 *              force = false, must not be publish if the local document is not the lastest one,
	 *              and must resolve at first.
	 *
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException publish did failed because of DIDBackend error.
	 * @throws DIDStoreException there is no activated DID or no lastest DID Document in DIDStore.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public void publish(DIDURL signKey, boolean force, String storepass)
			throws DIDInvalidException, InvalidKeyException,
			DIDStoreException, DIDBackendException {
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkState(getMetadata().attachedStore(), "Not attached with a store");
		checkState(signKey != null || getDefaultPublicKeyId() != null, "No effective controller");

		log.info("Publishing {}{}...", getSubject(), force ? " in force mode" : "");

		if (!isGenuine()) {
			log.error("Publish failed because document is not genuine.");
			throw new DIDNotGenuineException(getSubject().toString());
		}

		if (isDeactivated()) {
			log.error("Publish failed because DID is deactivated.");
			throw new DIDDeactivatedException(getSubject().toString());
		}

		if (isExpired() && !force) {
			log.error("Publish failed because document is expired.");
			log.info("You can publish the expired document using force mode.");
			throw new DIDExpiredException(getSubject().toString());
		}

		String lastTxid = null;
		String reolvedSignautre = null;
		DIDDocument resolvedDoc = getSubject().resolve(true);
		if (resolvedDoc != null) {
			if (resolvedDoc.isDeactivated()) {
				getMetadata().setDeactivated(true);
				saveMetadata();

				log.error("Publish failed because DID is deactivated.");
				throw new DIDDeactivatedException(getSubject().toString());
			}

			reolvedSignautre = resolvedDoc.getProof().getSignature();

			if (!force) {
				String localPrevSignature = getMetadata().getPreviousSignature();
				String localSignature = getMetadata().getSignature();

				if (localPrevSignature == null && localSignature == null) {
					log.error("Missing signatures information, " +
							"DID SDK dosen't know how to handle it, " +
							"use force mode to ignore checks.");
					throw new DIDNotUpToDateException(getSubject().toString());
				} else if (localPrevSignature == null || localSignature == null) {
					String ls = localPrevSignature != null ? localPrevSignature : localSignature;
					if (!ls.equals(reolvedSignautre)) {
						log.error("Current copy not based on the lastest on-chain copy, signature mismatch.");
						throw new DIDNotUpToDateException(getSubject().toString());
					}
				} else {
					if (!localSignature.equals(reolvedSignautre) &&
						!localPrevSignature.equals(reolvedSignautre)) {
						log.error("Current copy not based on the lastest on-chain copy, signature mismatch.");
						throw new DIDNotUpToDateException(getSubject().toString());
					}
				}
			}

			lastTxid = resolvedDoc.getMetadata().getTransactionId();
		}

		if (signKey == null)
			signKey = getDefaultPublicKeyId();

		if (lastTxid == null || lastTxid.isEmpty()) {
			log.info("Try to publish[create] {}...", getSubject());
			DIDBackend.getInstance().createDid(this, signKey, storepass);
		} else {
			log.info("Try to publish[update] {}...", getSubject());
			DIDBackend.getInstance().updateDid(this, lastTxid, signKey, storepass);
		}

		getMetadata().setPreviousSignature(reolvedSignautre);
		getMetadata().setSignature(getProof().getSignature());
		saveMetadata();
	}

	/**
	 * Publish DID content(DIDDocument) to chain without force mode.
	 *
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException publish did failed because of DIDBackend error.
	 * @throws DIDStoreException there is no activated DID or no lastest DID Document in DIDStore.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public void publish(DIDURL signKey, String storepass)
			throws DIDInvalidException, DIDBackendException, DIDStoreException, InvalidKeyException {
		publish(signKey, false, storepass);
	}

	/**
	 * Publish DID content(DIDDocument) to chain.
	 *
	 * @param signKey the key to sign
	 * @param force force = true, must be publish whether the local document is lastest one or not;
	 *              force = false, must not be publish if the local document is not the lastest one,
	 *              and must resolve at first.
	 *
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException publish did failed because of DIDBackend error.
	 * @throws DIDStoreException there is no activated DID or no lastest DID Document in DIDStore.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public void publish(String signKey, boolean force, String storepass)
			throws DIDInvalidException, DIDBackendException, DIDStoreException, InvalidKeyException {
		DIDURL _signKey = signKey == null ? null : new DIDURL(getSubject(), signKey);
		publish(_signKey, force, storepass);
	}

	/**
	 * Publish DID content(DIDDocument) to chain without force mode.
	 *
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException publish did failed because of DIDBackend error.
	 * @throws DIDStoreException there is no activated DID or no lastest DID Document in DIDStore.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public void publish(String signKey, String storepass)
			throws DIDInvalidException, DIDBackendException, DIDStoreException, InvalidKeyException {
		publish(signKey, false, storepass);
	}

	/**
	 * Publish DID content(DIDDocument) to chain without force mode.
	 * Specify the default key to sign.
	 *
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException publish did failed because of DIDBackend error.
	 * @throws DIDStoreException there is no activated DID or no lastest DID Document in DIDStore.
	 */
	public void publish(String storepass) throws DIDInvalidException,
			InvalidKeyException, DIDBackendException, DIDStoreException {
		publish((DIDURL)null, storepass);
	}

	/**
	 * Publish DID content(DIDDocument) to chain with asynchronous mode.
	 *
	 * @param signKey the key to sign
	 * @param force force = true, must be publish whether the local document is lastest one or not;
	 *              force = false, must not be publish if the local document is not the lastest one,
	 *              and must resolve at first.
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> publishAsync(DIDURL signKey, boolean force,
			String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				publish(signKey, force, storepass);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Publish DID content(DIDDocument) to chain with asynchronous mode.
	 *
	 * @param signKey the key to sign
	 * @param force force = true, must be publish whether the local document is lastest one or not;
	 *              force = false, must not be publish if the local document is not the lastest one,
	 *              and must resolve at first.
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> publishAsync(String signKey, boolean force,
			String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				publish(signKey, force, storepass);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Publish DID content(DIDDocument) to chain with asynchronous mode.
	 * Also this method is defined without force mode.
	 *
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> publishAsync(DIDURL signKey, String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				publish(signKey, storepass);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Publish DID content(DIDDocument) to chain with asynchronous mode.
	 * Also this method is defined without force mode.
	 *
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> publishAsync(String signKey, String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				publish(signKey, storepass);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Publish DID content(DIDDocument) to chain with asynchronous mode.
	 * Also this method is defined without force mode and specify the default key to sign.
	 *
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> publishAsync(String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				publish(storepass);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Deactivate self use authentication key.
	 *
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @throws DIDInvalidException the current DID is invalid
	 * @throws InvalidKeyException there is no an authentication key
	 * @throws DIDStoreException deactivate did failed because of did store error
	 * @throws DIDBackendException deactivate did failed because of did backend error
	 */
	public void deactivate(DIDURL signKey, String storepass)
			throws DIDInvalidException, InvalidKeyException, DIDStoreException, DIDBackendException {
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkState(getMetadata().attachedStore(), "Not attached with a store");
		checkState(signKey != null || getDefaultPublicKeyId() != null, "No effective controller");

		// Document should use the IDChain's copy
		DIDDocument doc = getSubject().resolve(true);
		if (doc == null)
			throw new DIDNotFoundException(getSubject().toString());
		else if (doc.isDeactivated())
			throw new DIDDeactivatedException(getSubject().toString());
		else
			doc.getMetadata().setStore(getStore());

		if (signKey == null) {
			signKey = doc.getDefaultPublicKeyId();
		} else {
			if (!doc.isAuthenticationKey(signKey))
				throw new InvalidKeyException("Not an authentication key: " + signKey);
		}

		DIDBackend.getInstance().deactivateDid(doc, signKey, storepass);

		if (!getSignature().equals(doc.getSignature()))
			getStore().storeDid(doc);
	}

	/**
	 * Deactivate self use authentication key.
	 *
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @throws DIDInvalidException the current DID is invalid
	 * @throws InvalidKeyException there is no an authentication key
	 * @throws DIDStoreException deactivate did failed because of did store error
	 * @throws DIDBackendException deactivate did failed because of did backend error
	 */
	public void deactivate(String signKey, String storepass)
			throws DIDInvalidException, InvalidKeyException, DIDStoreException, DIDBackendException {
		DIDURL _signKey = signKey == null ? null : new DIDURL(getSubject(), signKey);;
		deactivate(_signKey, storepass);
	}

	/**
	 * Deactivate self use authentication key.
	 * Specify the default key to sign.
	 *
	 * @param storepass the password for DIDStore
	 * @throws DIDInvalidException the current DID is invalid
	 * @throws InvalidKeyException there is no an authentication key
	 * @throws DIDStoreException deactivate did failed because of did store error
	 * @throws DIDBackendException deactivate did failed because of did backend error
	 */
	public void deactivate(String storepass)
			throws DIDInvalidException, InvalidKeyException, DIDStoreException, DIDBackendException {
		deactivate((DIDURL)null, storepass);
	}

	/**
	 * Deactivate self use authentication key with asynchronous mode.
	 *
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> deactivateAsync(DIDURL signKey, String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				deactivate(signKey, storepass);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Deactivate self use authentication key with asynchronous mode.
	 *
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> deactivateAsync(String signKey, String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				deactivate(signKey, storepass);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Deactivate self use authentication key with asynchronous mode.
	 * Specify the default key to sign.
	 *
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> deactivateAsync(String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				deactivate(storepass);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Deactivate target DID by authorizor's DID.
	 *
	 * @param target the target DID
	 * @param signKey the authorizor's key to sign
	 * @param storepass the password for DIDStore
	 * @throws DIDInvalidException the target DID is invalid
	 * @throws InvalidKeyException there is no an authentication key.
	 * @throws DIDStoreException deactivate did failed because of did store error.
	 * @throws DIDBackendException deactivate did failed because of did backend error.
	 */
	public void deactivate(DID target, DIDURL signKey, String storepass)
			throws DIDInvalidException, InvalidKeyException, DIDStoreException, DIDBackendException {
		checkArgument(target != null, "Invalid target DID");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkState(getMetadata().attachedStore(), "Not attached with a store");
		checkState(signKey != null || getDefaultPublicKeyId() != null, "No effective controller");

		DIDDocument targetDoc = target.resolve(true);
		if (targetDoc == null)
			throw new DIDNotFoundException(target.toString());
		else if (targetDoc.isDeactivated())
			throw new DIDDeactivatedException(target.toString());

		if (targetDoc.getAuthorizationKeyCount() == 0)
			throw new InvalidKeyException("No authorization key from: " + target);

		List<PublicKey> candidatePks = null;
		if (signKey == null) {
			candidatePks = this.getAuthenticationKeys();
		} else {
			PublicKey pk = getAuthenticationKey(signKey);
			if (pk == null)
				throw new InvalidKeyException("Not an authentication key: " + signKey);
			candidatePks = new ArrayList<PublicKey>(1);
			candidatePks.add(pk);
		}

		// Lookup the authorization key id in the target doc
		DIDURL realSignKey = null;
		DIDURL targetSignKey = null;
		lookup: for (PublicKey candidatePk : candidatePks) {
			for (PublicKey pk : targetDoc.getAuthorizationKeys()) {
				if (!pk.getController().equals(getSubject()))
					continue;

				if (pk.getPublicKeyBase58().equals(candidatePk.getPublicKeyBase58())) {
					realSignKey = candidatePk.getId();
					targetSignKey = pk.getId();
					break lookup;
				}
			}
		}

		if (realSignKey == null || targetSignKey == null)
			throw new InvalidKeyException("No matched authorization key.");

		DIDBackend.getInstance().deactivateDid(targetDoc, targetSignKey,
				this, realSignKey, storepass);
	}

	/**
	 * Deactivate target DID by authorizor's DID.
	 *
	 * @param target the target DID string
	 * @param signKey the authorizor's key to sign
	 * @param storepass the password for DIDStore
	 * @throws DIDInvalidException the target DID is invalid
	 * @throws InvalidKeyException there is no an authentication key.
	 * @throws DIDStoreException deactivate did failed because of did store error.
	 * @throws DIDBackendException deactivate did failed because of did backend error.
	 */
	public void deactivate(String target, String signKey, String storepass)
			throws DIDInvalidException, InvalidKeyException, DIDStoreException, DIDBackendException {
		DID _target = null;
		DIDURL _signKey = null;
		try {
			_target = new DID(target);
			_signKey = signKey == null ? null : new DIDURL(getSubject(), signKey);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		deactivate(_target, _signKey, storepass);
	}

	/**
	 * Deactivate target DID by authorizor's DID.
	 *
	 * @param target the target DID string
	 * @param storepass the password for DIDStore
	 * @throws DIDInvalidException the target DID is invalid
	 * @throws InvalidKeyException there is no an authentication key.
	 * @throws DIDStoreException deactivate did failed because of did store error.
	 * @throws DIDBackendException deactivate did failed because of did backend error.
	 */
	public void deactivate(DID target, String storepass)
			throws DIDInvalidException, InvalidKeyException, DIDStoreException, DIDBackendException {
		deactivate(target, null, storepass);
	}

	/**
	 * Deactivate target DID by authorizor's DID with asynchronous mode.
	 *
	 * @param target the target DID
	 * @param signKey the authorizor's key to sign
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> deactivateDidAsync(DID target,
			DIDURL signKey, String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				deactivate(target, signKey, storepass);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Deactivate target DID by authorizor's DID with asynchronous mode.
	 *
	 * @param target the target DID
	 * @param did the authorizor's DID.
	 * @param confirms the count of confirms
	 * @param signKey the authorizor's key to sign
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> deactivateDidAsync(String target,
			String signKey, String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				deactivate(target, signKey, storepass);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Deactivate target DID by authorizor's DID with asynchronous mode.
	 *
	 * @param target the target DID
	 * @param did the authorizor's DID, use the default key to sign.
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> deactivateDidAsync(DID target, String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				deactivate(target, storepass);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Parse a DIDDocument object from from a string JSON representation.
	 *
	 * @param content the string JSON content for building the object.
	 * @return the DIDDocument object.
	 * @throws DIDSyntaxException if a parse error occurs.
	 */
	public static DIDDocument parse(String content) throws DIDSyntaxException {
		return parse(content, DIDDocument.class);
	}

	/**
	 * Parse a DIDDocument object from from a Reader object.
	 *
	 * @param src Reader object used to read JSON content for building the object
	 * @return the DIDDocument object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static DIDDocument parse(Reader src)
			throws DIDSyntaxException, IOException {
		return parse(src, DIDDocument.class);
	}

	/**
	 * Parse a DIDDocument object from from a InputStream object.
	 *
	 * @param src InputStream object used to read JSON content for building the object
	 * @return the DIDDocument object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static DIDDocument parse(InputStream src)
			throws DIDSyntaxException, IOException {
		return parse(src, DIDDocument.class);
	}

	/**
	 * Parse a DIDDocument object from from a File object.
	 *
	 * @param src File object used to read JSON content for building the object
	 * @return the DIDDocument object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static DIDDocument parse(File src)
			throws DIDSyntaxException, IOException {
		return parse(src, DIDDocument.class);
	}

	/**
	 * Parse a DIDDocument object from from a string JSON representation.
	 *
	 * @param content the string JSON content for building the object
	 * @return the DIDDocument object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @deprecated use {@link #parse(String)} instead
	 */
	@Deprecated
	public static DIDDocument fromJson(String content) throws DIDSyntaxException {
		return parse(content);
	}

	/**
	 * Parse a DIDDocument object from from a Reader object.
	 *
	 * @param src Reader object used to read JSON content for building the object
	 * @return the DIDDocument object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(Reader)} instead
	 */
	@Deprecated
	public static DIDDocument fromJson(Reader src)
			throws DIDSyntaxException, IOException {
		return parse(src);
	}

	/**
	 * Parse a DIDDocument object from from a InputStream object.
	 *
	 * @param src InputStream object used to read JSON content for building the object
	 * @return the DIDDocument object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(InputStream)} instead
	 */
	@Deprecated
	public static DIDDocument fromJson(InputStream src)
			throws DIDSyntaxException, IOException {
		return parse(src);
	}

	/**
	 * Parse a DIDDocument object from from a File object.
	 *
	 * @param src File object used to read JSON content for building the object
	 * @return the DIDDocument object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(File)} instead
	 */
	@Deprecated
	public static DIDDocument fromJson(File src)
			throws DIDSyntaxException, IOException {
		return parse(src);
	}

	/**
     * Builder object to create or modify the DIDDocument.
	 */
	public static class Builder {
		private DIDDocument document;
		private DIDDocument controllerDoc;

		/**
		 * Constructs DID Document Builder with given DID and DIDStore.
		 *
		 * @param did the specified DID
		 * @param store the DIDStore object
		 */
		protected Builder(DID did, DIDStore store) {
			this.document = new DIDDocument(did);
			this.document.getMetadata().setStore(store);
		}

		/**
		 * Constructs DID Document Builder with given customizedDid and DIDStore.
		 *
		 * @param did the specified DID
		 * @param store the DIDStore object
		 */
		protected Builder(DID did, DIDDocument controller, DIDStore store) {
			this.document = new DIDDocument(did, controller);
			this.document.getMetadata().setStore(store);
			this.controllerDoc = controller;
		}

		/**
		 * Constructs DID Document Builder with given DID Document.
		 *
		 * @param doc the DID Document object
		 */
		protected Builder(DIDDocument doc) {
			this.document = doc;
		}

		public Builder(DIDDocument doc, DIDDocument controller) {
			this.document = doc;
			// if (controller.getMetadata().attachedStore())
			//	this.document.getMetadata().setStore(controller.getMetadata().getStore());
			this.controllerDoc = controller;
		}

		/**
		 * Get document subject from did document builder.
		 *
		 * @return the owner of did document builder
		 */
		public DID getSubject() {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			return document.getSubject();
		}

		private void invalidateProof() {
			if (document.proofs != null && !document.proofs.isEmpty())
				document.proofs.clear();
		}

		/**
		 * Add a new controller to the customized DID document.
		 *
		 * @param controller the new controller's DID
		 * @return the Builder object
		 * @throws DIDResolveException if failed resolve the new controller's DID
		 */
		public Builder addController(DID controller) throws DIDResolveException {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (document.controllers == null)
				throw new UnsupportedOperationException("Not a customized DID document");

			if (document.controllers.contains(controller))
				throw new IllegalArgumentException("Controller already exists");

			DIDDocument controllerDoc = controller.resolve(true);
			if (controllerDoc == null)
				throw new IllegalArgumentException("Controller'd DID not exists");

			if (!controllerDoc.isValid())
				throw new IllegalArgumentException("Controller'd DID document is invalid");

			document.controllers.add(controller);
			document.controllerDocs.put(controller, controllerDoc);

			invalidateProof();
			return this;
		}

		/**
		 * Add a new controller to the customized DID document.
		 *
		 * @param controller the new controller's DID
		 * @return the Builder object
		 * @throws DIDResolveException if failed resolve the new controller's DID
		 */
		public Builder addController(String controller) throws DIDResolveException {
			try {
				return addController(new DID(controller));
			} catch (MalformedDIDException e) {
				throw new IllegalArgumentException();
			}
		}

		/**
		 * Set multiple signature for multi-controllers DID document.
		 *
		 * @param m the required signature count
		 * @return the Builder object
		 */
		public Builder setMultiSignature(int m) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (document.controllers == null || document.controllers.size() <= 1)
				throw new UnsupportedOperationException("Not a multi-controllers customized DID document");

			int n = document.controllers.size();
			if (m > n)
				throw new IllegalArgumentException("Signature count exceeds the upper limit");

			if (document.multisig != null) {
				if (document.multisig.m() == m && document.multisig.n() == n)
					return this; // do nothing
			}

			document.multisig = new MultiSignature(m, n);

			invalidateProof();
			return this;
		}

		/**
		 * Remove controller from the customized DID document.
		 *
		 * @param controller the controller's DID to be remove
		 * @return the Builder object
		 */
		public Builder removeController(DID controller) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (document.controllers == null)
				throw new UnsupportedOperationException("Document does not have controller");

			if (document.controllers.size() == 1)
				throw new UnsupportedOperationException("Document should has at least one controller");

			if (document.controllers.remove(controller)) {
				document.controllerDocs.remove(controller);
				invalidateProof();
			}

			return this;
		}

		/**
		 * Remove controller from the customized DID document.
		 *
		 * @param controller the controller's DID to be remove
		 * @return the Builder object
		 */
		public Builder removeController(String controller) {
			try {
				return removeController(new DID(controller));
			} catch (MalformedDIDException e) {
				throw new IllegalArgumentException();
			}
		}

		private void addPublicKey(PublicKey key) {
			if (key.id == null || key.controller == null ||
					key.keyBase58 == null || key.keyBase58.isEmpty())
				throw new IllegalArgumentException();

			if ( Base58.decode(key.keyBase58).length != HDKey.PUBLICKEY_BYTES)
				throw new IllegalArgumentException("Invalid public key.");

	        if (document.publicKeys == null) {
	        	document.publicKeys = new TreeMap<DIDURL, PublicKey>();
	        } else {
	            // Check the existence, both id and keyBase58
	            for (PublicKey pk : document.publicKeys.values()) {
	                if (pk.getId().equals(key.getId()))
	                    throw new DIDObjectAlreadyExistException("PublicKey id '"
	                            + key.getId() + "' already exist.");

	                if (pk.getPublicKeyBase58().equals(key.getPublicKeyBase58()))
	                    throw new DIDObjectAlreadyExistException("PublicKey '"
	                            + key.getPublicKeyBase58() + "' already exist.");
	            }
	        }

	        document.publicKeys.put(key.getId(), key);
	        invalidateProof();
		}

		/**
		 * Add PublicKey to did document builder.
		 *
		 * @param id the key id
		 * @param controller the owner of public key
		 * @param pk the public key base58 string
		 * @return the DID Document Builder object
		 */
		public Builder addPublicKey(DIDURL id, DID controller, String pk) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			addPublicKey(new PublicKey(id, controller, pk));
			return this;
		}

		/**
		 * Add PublicKey to did document builder.
		 *
		 * @param id the key id string
		 * @param controller the owner of public key
		 * @param pk the public key base58 string
		 * @return the DID Document Builder object
		 */
		public Builder addPublicKey(String id, String controller, String pk) {
			DID _controller = null;
			try {
				_controller = new DID(controller);
			} catch (MalformedDIDException e) {
				throw new IllegalArgumentException();
			}

			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return addPublicKey(_id, _controller, pk);
		}

		/**
		 * Remove PublicKey with the specified key id.
		 *
		 * @param id the key id
		 * @param force the owner of public key
		 * @return the DID Document Builder object
		 */
		public Builder removePublicKey(DIDURL id, boolean force) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (id == null)
				throw new IllegalArgumentException();

	        PublicKey pk = document.getEntry(document.publicKeys, id);
	        if (pk == null)
	            throw new DIDObjectNotExistException("PublicKey id '"
	                    + id + "' not exist.");

	        // Can not remove default public key
	        if (document.defaultPublicKey != null && document.defaultPublicKey.getId().equals(id))
	            throw new UnsupportedOperationException(
	                    "Cannot remove the default PublicKey.");

	        if (!force) {
	            if (pk.isAuthenticationKey() || pk.isAuthorizationKey())
	                throw new UnsupportedOperationException("Key has references.");
	        }

	        if (document.removeEntry(document.publicKeys, id) != null) {
		        try {
		        	// TODO: should delete the loosed private key when store the document
		            if (document.getMetadata().attachedStore())
		                document.getMetadata().getStore().deletePrivateKey(getSubject(), id);
		        } catch (DIDStoreException ignore) {
		            log.error("INTERNAL - Remove private key", ignore);
		        }

		        invalidateProof();
	        }

			return this;
		}

		/**
		 * Remove PublicKey matched the specified key id.
		 *
		 * @param id the key id
	     * @param force force = true, the matched key must be removed.
	     *              force = false, the matched key must not be removed if this key is authentiacation
	     *              or authorization key.
		 * @return the DID Document Builder object
		 */
		public Builder removePublicKey(String id, boolean force) {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return removePublicKey(_id, force);
		}

		/**
		 * Remove PublicKey matched the specified key id without force module.
		 *
		 * @param id the key id
		 * @return the DID Document Builder object
		 */
		public Builder removePublicKey(DIDURL id) {
			return removePublicKey(id, false);
		}

		/**
		 * Remove PublicKey matched the specified key id without force module.
		 *
		 * @param id the key id
		 * @return the DID Document Builder object
		 */
		public Builder removePublicKey(String id) {
			return removePublicKey(id, false);
		}

		/**
		 * Add the exist Public Key matched the key id to be Authentication key.
		 *
		 * @param id the key id
		 * @return the DID Document Builder object
		 */
		public Builder addAuthenticationKey(DIDURL id) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (id == null)
				throw new IllegalArgumentException();

	        PublicKey key = document.getEntry(document.publicKeys, id);
	        if (key == null)
	            throw new DIDObjectNotExistException("PublicKey '" + id + "' not exists.");

	        // Check the controller is current DID subject
	        if (!key.getController().equals(getSubject()))
	            throw new UnsupportedOperationException("Key cannot used for authentication.");

	        if (!key.isAuthenticationKey()) {
	        	key.setAuthenticationKey(true);
	        	invalidateProof();
	        }

			return this;
		}

		/**
		 * Add the exist Public Key matched the key id to be Authentication key.
		 *
		 * @param id the key id string
		 * @return the DID Document Builder object
		 */
		public Builder addAuthenticationKey(String id) {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return addAuthenticationKey(_id);
		}

		/**
		 * Add the PublicKey named the key id to be an authentication key.
		 * It is failed if the key id exist but the public key base58 string is not same as the given pk string.
		 *
		 * @param id the key id
		 * @param pk the public key base58 string
		 * @return the DID Document Builder
		 */
		public Builder addAuthenticationKey(DIDURL id, String pk) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			PublicKey key = new PublicKey(id, getSubject(), pk);
			key.setAuthenticationKey(true);
			addPublicKey(key);

			return this;
		}

		/**
		 * Add the PublicKey named the key id to be an authentication key.
		 * It is failed if the key id exist but the public key base58 string is not same as the given pk string.
		 *
		 * @param id the key id string
		 * @param pk the public key base58 string
		 * @return the DID Document Builder
		 */
		public Builder addAuthenticationKey(String id, String pk) {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return addAuthenticationKey(_id, pk);
		}

		/**
		 * Remove Authentication Key matched the given id.
		 *
		 * @param id the key id
		 * @return the DID Document Builder
		 */
		public Builder removeAuthenticationKey(DIDURL id) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (id == null)
				throw new IllegalArgumentException();

	        PublicKey key = document.getEntry(document.publicKeys, id);
	        if (key == null)
	            throw new DIDObjectNotExistException("PublicKey id '"
	                    + id + "' not exist.");

	        if (!key.isAuthenticationKey())
	            throw new DIDObjectNotExistException("PublicKey id '"
	                    + id + "' not an authentication key.");

	        // Can not remove default public key
	        if (document.defaultPublicKey != null && document.defaultPublicKey.getId().equals(id))
	            throw new UnsupportedOperationException(
	                    "Cannot remove the default PublicKey from authentication.");

	        if (key.isAuthenticationKey()) {
	        	key.setAuthenticationKey(false);
	        	invalidateProof();
	        }

			return this;
		}

		/**
		 * Remove Authentication Key matched the given id.
		 *
		 * @param id the key id string
		 * @return the DID Document Builder
		 */
		public Builder removeAuthenticationKey(String id) {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return removeAuthenticationKey(_id);
		}

		/**
		 * Add the exist Public Key matched the key id to be Authorization key.
		 *
		 * @param id the key id
		 * @return the DID Document Builder
		 */
		public Builder addAuthorizationKey(DIDURL id) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (id == null)
				throw new IllegalArgumentException();

	        PublicKey key = document.getEntry(document.publicKeys, id);
	        if (key == null)
	            throw new DIDObjectNotExistException("PublicKey '" + id + "' not exists.");

	        // Can not authorize to self
	        if (key.getController().equals(getSubject()))
	            throw new UnsupportedOperationException("Key cannot used for authorization.");

	        if (!key.isAuthorizationKey()) {
	        	key.setAuthorizationKey(true);
	        	invalidateProof();
	        }

			return this;
		}

		/**
		 * Add the exist Public Key matched the key id to be Authorization Key.
		 *
		 * @param id the key id string
		 * @return the DID Document Builder
		 */
		public Builder addAuthorizationKey(String id) {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return addAuthorizationKey(_id);
		}

		/**
		 * Add the PublicKey named key id to be Authorization Key.
		 * It is failed if the key id exist but the public key base58 string is not same as the given pk string.
		 *
		 * @param id the key id
		 * @param controller the owner of public key
		 * @param pk the public key base58 string
		 * @return the DID Document Builder
		 */
		public Builder addAuthorizationKey(DIDURL id, DID controller, String pk) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			// Can not authorize to self
			if (controller.equals(getSubject()))
				throw new UnsupportedOperationException("Invalid controller.");

			PublicKey key = new PublicKey(id, controller, pk);
			key.setAuthorizationKey(true);
			addPublicKey(key);

			return this;
		}

		/**
		 * Add the PublicKey named key id to be Authorization Key.
		 * It is failed if the key id exist but the public key base58 string is not same as the given pk string.
		 *
		 * @param id the key id string
		 * @param controller the owner of public key
		 * @param pk the public key base58 string
		 * @return the DID Document Builder
		 */
		public Builder addAuthorizationKey(String id, String controller, String pk) {
			DID _controller = null;
			try {
				_controller = new DID(controller);
			} catch (MalformedDIDException e) {
				throw new IllegalArgumentException();
			}

			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return addAuthorizationKey(_id, _controller, pk);
		}

		/**
         * Add the specified key to be an Authorization key.
         * This specified key is the key of specified controller.
         * Authentication is the mechanism by which the controller(s) of a DID can
         * cryptographically prove that they are associated with that DID.
         * A DID Document must include authentication key.
		 *
		 * @param id the key id
		 * @param controller the owner of 'key'
		 * @param key the key of controller to be an Authorization key.
		 * @return the DID Document Builder
		 * @throws DIDResolveException resolve controller failed.
		 * @throws InvalidKeyException the key is not an authentication key.
		 */
		public Builder authorizationDid(DIDURL id, DID controller, DIDURL key)
				throws DIDNotFoundException, DIDResolveException, InvalidKeyException {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (id == null || controller == null)
				throw new IllegalArgumentException();

			// Can not authorize to self
			if (controller.equals(getSubject()))
				throw new UnsupportedOperationException("Invalid controller.");

			DIDDocument controllerDoc = controller.resolve();
			if (controllerDoc == null)
				throw new DIDNotFoundException(id.toString());

			if (key == null)
				key = controllerDoc.getDefaultPublicKeyId();

			// Check the key should be a authentication key.
			PublicKey targetPk = controllerDoc.getAuthenticationKey(key);
			if (targetPk == null)
				throw new InvalidKeyException(key.toString());

			PublicKey pk = new PublicKey(id, targetPk.getType(),
					controller, targetPk.getPublicKeyBase58());
			pk.setAuthorizationKey(true);
			addPublicKey(pk);

			return this;
		}

		/**
         * Add Authorization key to Authentication array according to DID.
         * Authentication is the mechanism by which the controller(s) of a DID can
         * cryptographically prove that they are associated with that DID.
         * A DID Document must include authentication key.
		 *
		 * @param id the key id string
		 * @param controller the owner of public key
		 * @return the DID Document Builder
		 * @throws DIDResolveException resolve controller failed.
		 * @throws InvalidKeyException the key is not an authentication key.
		 */
		public Builder authorizationDid(DIDURL id, DID controller)
				throws DIDNotFoundException, DIDResolveException, InvalidKeyException {
			return authorizationDid(id, controller, null);
		}

		/**
         * Add Authorization key to Authentication array according to DID.
         * Authentication is the mechanism by which the controller(s) of a DID can
         * cryptographically prove that they are associated with that DID.
         * A DID Document must include authentication key.
		 *
		 * @param id the key id string
		 * @param controller the owner of public key
		 * @param key the key of controller to be an Authorization key.
		 * @return the DID Document Builder
		 * @throws DIDResolveException resolve controller failed.
		 * @throws InvalidKeyException the key is not an authentication key.
		 */
		public Builder authorizationDid(String id, String controller, String key)
				throws DIDNotFoundException, DIDResolveException, DIDBackendException, InvalidKeyException {
			DID controllerId = null;
			try {
				controllerId = new DID(controller);
			} catch (MalformedDIDException e) {
				throw new IllegalArgumentException(e);
			}

			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			DIDURL _key = key == null ? null : new DIDURL(controllerId, key);
			return authorizationDid(_id, controllerId, _key);
		}

		/**
         * Add Authorization key to Authentication array according to DID.
         * Authentication is the mechanism by which the controller(s) of a DID can
         * cryptographically prove that they are associated with that DID.
         * A DID Document must include authentication key.
		 *
		 * @param id the key id string
		 * @param controller the owner of public key
		 * @return the DID Document Builder
		 * @throws DIDResolveException resolve controller failed.
		 * @throws InvalidKeyException the key is not an authentication key.
		 */
		public Builder authorizationDid(String id, String controller)
				throws DIDNotFoundException, DIDResolveException, DIDBackendException, InvalidKeyException {
			return authorizationDid(id, controller, null);
		}

		/**
		 * Remove the Authorization Key matched the given id.
		 *
		 * @param id the key id
		 * @return the DID Document Builder
		 */
		public Builder removeAuthorizationKey(DIDURL id) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (id == null)
				throw new IllegalArgumentException();

	        PublicKey key = document.getEntry(document.publicKeys, id);
	        if (key == null)
	            throw new DIDObjectNotExistException("PublicKey id '"
	                    + id + "' not exist.");

	        if (!key.isAuthorizationKey())
	            throw new DIDObjectNotExistException("PublicKey id '"
	                    + id + "' not an authorization key.");

	        if (key.isAuthorizationKey()) {
	        	key.setAuthorizationKey(false);
	        	invalidateProof();
	        }

			return this;
		}

		/**
		 * Remove the Authorization Key matched the given id.
		 *
		 * @param id the key id string
		 * @return the DID Document Builder
		 */
		public Builder removeAuthorizationKey(String id) {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return removeAuthorizationKey(_id);
		}

		/**
		 * Add Credentail to DID Document Builder.
		 *
		 * @param vc the Verifiable Credential object
		 * @return the DID Document Builder
		 */
		public Builder addCredential(VerifiableCredential vc) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (vc == null)
				throw new IllegalArgumentException();

	        // Check the credential belongs to current DID.
	        if (!vc.getSubject().getId().equals(getSubject()))
	            throw new UnsupportedOperationException("Credential not owned by self.");

	        if (document.credentials == null) {
	            document.credentials = new TreeMap<DIDURL, VerifiableCredential>();
	        } else {
	            if (document.credentials.containsKey(vc.getId()))
	                throw new DIDObjectAlreadyExistException("Credential '"
	                        + vc.getId() + "' already exist.");
	        }

	        document.credentials.put(vc.getId(), vc);
	        invalidateProof();

			return this;
		}

		/**
		 * Add Credential with the given values.
		 *
		 * @param id the Credential id
		 * @param types the Credential types set
		 * @param subject the Credential subject(key/value)
		 * @param expirationDate the Credential expires time
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(DIDURL id, String[] types,
				Map<String, Object> subject, Date expirationDate, String storepass)
				throws DIDStoreException, InvalidKeyException {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (id == null || subject == null || subject.isEmpty() ||
					storepass == null || storepass.isEmpty())
				throw new IllegalArgumentException();

			Issuer issuer = new Issuer(document);
			VerifiableCredential.Builder cb = issuer.issueFor(document.getSubject());
			if (types == null)
				types = new String[]{ "SelfProclaimedCredential" };

			if (expirationDate == null)
				expirationDate = document.getExpires();

			try {
				VerifiableCredential vc = cb.id(id)
						.type(types)
						.properties(subject)
						.expirationDate(expirationDate)
						.seal(storepass);

				addCredential(vc);
			} catch (MalformedCredentialException ignore) {
				// Should never happen
				log.error("INTERNAL - Create credential", ignore);
			}

			return this;
		}

		/**
		 * Add Credential with the given values.
		 *
		 * @param id the Credential id string
		 * @param types the Credential types set
		 * @param subject the Credential subject(key/value)
		 * @param expirationDate the Credential expires time
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(String id, String[] types,
				Map<String, Object> subject, Date expirationDate, String storepass)
				throws DIDStoreException, InvalidKeyException {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return addCredential(_id, types, subject, expirationDate, storepass);
		}

		/**
		 * Add SelfProclaimed Credential with the given values.
		 *
		 * @param id the Credential id
		 * @param subject the Credential subject(key/value)
		 * @param expirationDate the Credential expires time
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(DIDURL id, Map<String, Object> subject,
				Date expirationDate, String storepass)
				throws DIDStoreException, InvalidKeyException {
			return addCredential(id, null, subject, expirationDate, storepass);
		}

		/**
		 * Add SelfProclaimed Credential with the given values.
		 *
		 * @param id the Credential id string
		 * @param subject the Credential subject(key/value)
		 * @param expirationDate the Credential expires time
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(String id, Map<String, Object> subject,
				Date expirationDate, String storepass)
				throws DIDStoreException, InvalidKeyException {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return addCredential(_id, subject, expirationDate, storepass);
		}

		/**
		 * Add Credential with the given values.
		 * The Credential expires time is the document expires time of Credential subject id.
		 *
		 * @param id the Credential id
		 * @param types the Credential id
		 * @param subject the Credential subject(key/value)
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(DIDURL id, String[] types,
				Map<String, Object> subject, String storepass)
				throws DIDStoreException, InvalidKeyException {
			return addCredential(id, types, subject, null, storepass);
		}

		/**
		 * Add Credential with the given values.
		 * The Credential expires time is the document expires time of Credential subject id.
		 *
		 * @param id the Credential id string
		 * @param types the Credential id
		 * @param subject the Credential subject(key/value)
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(String id, String[] types,
				Map<String, Object> subject, String storepass)
				throws DIDStoreException, InvalidKeyException {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return addCredential(_id, types, subject, storepass);
		}

		/**
		 * Add SelfProclaimed Credential with the given values.
		 * The Credential expires time is the document expires time of Credential subject id.
		 *
		 * @param id the Credential id
		 * @param subject the Credential subject(key/value)
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(DIDURL id, Map<String, Object> subject,
				String storepass)
				throws DIDStoreException, InvalidKeyException {
			return addCredential(id, null, subject, null, storepass);
		}

		/**
		 * Add SelfProclaimed Credential with the given values.
		 * The Credential expires time is the document expires time of Credential subject id.
		 *
		 * @param id the Credential id string
		 * @param subject the Credential subject(key/value)
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(String id, Map<String, Object> subject,
				String storepass)
				throws DIDStoreException, InvalidKeyException {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return addCredential(_id, subject, storepass);
		}

		/**
		 * Add Credential with the given values.
		 * Credential subject supports json string.
		 *
		 * @param id the Credential id
		 * @param types the Credential types
		 * @param json the Credential subject(json string)
		 * @param expirationDate the Credential expires time
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(DIDURL id, String[] types,
				String json, Date expirationDate, String storepass)
				throws DIDStoreException, InvalidKeyException {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (id == null || json == null || json.isEmpty() ||
					storepass == null || storepass.isEmpty())
				throw new IllegalArgumentException();

			Issuer issuer = new Issuer(document);
			VerifiableCredential.Builder cb = issuer.issueFor(document.getSubject());
			if (types == null)
				types = new String[]{ "SelfProclaimedCredential" };

			if (expirationDate == null)
				expirationDate = document.expires;

			try {
				VerifiableCredential vc = cb.id(id)
						.type(types)
						.properties(json)
						.expirationDate(expirationDate)
						.seal(storepass);

				addCredential(vc);
			} catch (MalformedCredentialException ignore) {
				// Should never happen
				log.error("INTERNAL - Create credential", ignore);
			}

			return this;
		}

		/**
		 * Add Credential with the given values.
		 * Credential subject supports json string.
		 *
		 * @param id the Credential id string
		 * @param types the Credential types
		 * @param json the Credential subject(json string)
		 * @param expirationDate the Credential expires time
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(String id, String[] types,
				String json, Date expirationDate, String storepass)
				throws DIDStoreException, InvalidKeyException {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return addCredential(_id, types, json, expirationDate, storepass);
		}

		/**
		 * Add SelfProclaimed Credential with the given values.
		 * Credential subject supports json string.
		 *
		 * @param id the Credential id
		 * @param json the Credential subject(json string)
		 * @param expirationDate the Credential expires time
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(DIDURL id, String json,
				Date expirationDate, String storepass)
				throws DIDStoreException, InvalidKeyException {
			return addCredential(id, null, json, expirationDate, storepass);
		}

		/**
		 * Add SelfProclaimed Credential with the given values.
		 * Credential subject supports json string.
		 *
		 * @param id the Credential id string
		 * @param json the Credential subject(json string)
		 * @param expirationDate the Credential expires time
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(String id, String json,
				Date expirationDate, String storepass)
				throws DIDStoreException, InvalidKeyException {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return addCredential(_id, json, expirationDate, storepass);
		}

		/**
		 * Add Credential with the given values.
		 * Credential subject supports json string.
		 * The Credential expires time is the document expires time of Credential subject id.
		 *
		 * @param id the Credential id
		 * @param types the Credential types
		 * @param json the Credential subject(json string)
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(DIDURL id, String[] types,
				String json, String storepass)
				throws DIDStoreException, InvalidKeyException {
			return addCredential(id, types, json, null, storepass);
		}

		/**
		 * Add Credential with the given values.
		 * Credential subject supports json string.
		 * The Credential expires time is the document expires time of Credential subject id.
		 *
		 * @param id the Credential id
		 * @param types the Credential types
		 * @param json the Credential subject(json string)
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(String id, String[] types,
				String json, String storepass)
				throws DIDStoreException, InvalidKeyException {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return addCredential(_id, types, json, storepass);
		}

		/**
		 * Add SelfProclaimed Credential with the given values.
		 * Credential subject supports json string.
		 * The Credential expires time is the document expires time of Credential subject id.
		 *
		 * @param id the Credential id
		 * @param json the Credential subject(json string)
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(DIDURL id, String json, String storepass)
				throws DIDStoreException, InvalidKeyException {
			return addCredential(id, null, json, null, storepass);
		}

		/**
		 * Add SelfProclaimed Credential with the given values.
		 * Credential subject supports json string.
		 * The Credential expires time is the document expires time of Credential subject id.
		 *
		 * @param id the Credential id string
		 * @param json the Credential subject(json string)
		 * @param storepass the password for DIDStore
		 * @return the DID Document Builder
		 * @throws DIDStoreException there is no DID store to attach.
		 * @throws InvalidKeyException there is no authentication key.
		 */
		public Builder addCredential(String id, String json, String storepass)
				throws DIDStoreException, InvalidKeyException {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return addCredential(_id, json, storepass);
		}

		/**
		 * Remove Credential with the specified id.
		 *
		 * @param id the Credential id
		 * @return the DID Document Builder
		 */
		public Builder removeCredential(DIDURL id) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (id == null)
				throw new IllegalArgumentException();

			if (document.removeEntry(document.credentials, id) != null)
				invalidateProof();

			return this;
		}

		/**
		 * Remove Credential with the specified id.
		 *
		 * @param id the Credential id string
		 * @return the DID Document Builder
		 */
		public Builder removeCredential(String id) {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return removeCredential(_id);
		}

		/**
		 * Add Service.
		 *
		 * @param id the specified Service id
		 * @param type the Service type
		 * @param endpoint the service point's adderss
		 * @return the DID Document Builder
		 */
		public Builder addService(DIDURL id, String type, String endpoint) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (id == null || type == null || type.isEmpty() ||
					endpoint == null || endpoint.isEmpty() )
				throw new IllegalArgumentException();

			Service svc = new Service(id, type, endpoint);
	        if (document.services == null)
	        	document.services = new TreeMap<DIDURL, Service>();
	        else {
	            if (document.services.containsKey(svc.getId()))
	                throw new DIDObjectAlreadyExistException("Service '"
	                        + svc.getId() + "' already exist.");
	        }

	        document.services.put(svc.getId(), svc);
	        invalidateProof();

			return this;
		}

		/**
		 * Add Service.
		 *
		 * @param id the specified Service id string
		 * @param type the Service type
		 * @param endpoint the service point's adderss
		 * @return the DID Document Builder
		 */
		public Builder addService(String id, String type, String endpoint) {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return addService(_id, type, endpoint);
		}

        /**
         * Remove the Service with the specified id.
         *
         * @param id the Service id
         * @return the DID Document Builder
         */
		public Builder removeService(DIDURL id) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (id == null)
				throw new IllegalArgumentException();

			if (document.removeEntry(document.services, id) != null)
				invalidateProof();

			return this;
		}

        /**
         * Remove the Service with the specified id.
         *
         * @param id the Service id string
         * @return the DID Document Builder
         */
		public Builder removeService(String id) {
			DIDURL _id = id == null ? null : new DIDURL(getSubject(), id);
			return removeService(_id);
		}

		private Calendar getMaxExpires() {
			Calendar cal = Calendar.getInstance(Constants.UTC);
			cal.add(Calendar.YEAR, Constants.MAX_VALID_YEARS);
			return cal;
		}

		/**
		 * Set the current time to be expires time for DID Document Builder.
		 *
		 * @return the DID Document Builder
		 */
		public Builder setDefaultExpires() {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			document.expires = getMaxExpires().getTime();
			invalidateProof();

			return this;
		}

		/**
		 * Set the specified time to be expires time for DID Document Builder.
		 *
		 * @param expires the specified time
		 * @return the DID Document Builder
		 */
		public Builder setExpires(Date expires) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (expires == null)
				throw new IllegalArgumentException();

			Calendar cal = Calendar.getInstance(Constants.UTC);
			cal.setTime(expires);

			if (cal.after(getMaxExpires()))
				throw new IllegalArgumentException("Invalid date.");

			document.expires = expires;
			invalidateProof();

			return this;
		}

		/**
		 * Remove the proof that created by the specific controller.
		 *
		 * @param controller the controller's DID
		 * @return the DID Document Builder
		 */
		public Builder removeProof(DID controller) {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (document.proofs == null || document.proofs.isEmpty())
				return this;

			Proof matched = null;
			for (Proof proof : document.proofs.values()) {
				if (proof.getCreator().getDid().equals(controller)) {
					matched = proof;
					break;
				}
			}

			document.proofs.remove(matched.getCreator());
			return this;
		}

		/**
		 * Seal the document object, attach the generated proof to the
		 * document.
		 *
		 * @param storepass the password for DIDStore
		 * @return the DIDDocument object
		 * @throws InvalidKeyException if no valid sign key to seal the document
		 * @throws MalformedDocumentException if the DIDDocument is malformed
		 * @throws DIDStoreException if an error occurs when access DID store
		 */
		public DIDDocument seal(String storepass)
				throws MalformedDocumentException, DIDStoreException {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (storepass == null || storepass.isEmpty())
				throw new IllegalArgumentException();

			if (document.proofs != null &&
					((document.multisig == null && document.proofs.size() == 1) ||
					(document.multisig != null && document.proofs.size() == document.multisig.m())))
				throw new IllegalStateException("Document already sealed.");

			if (document.proofs == null || document.proofs.size() == 0) {
				if (document.getExpires() == null)
					setDefaultExpires();
			}

			document.sanitize(false);

			DIDDocument	signerDoc;
			if (!document.isCustomizedDid()) {
				signerDoc = document;
			} else {
				if (controllerDoc != null)
					signerDoc = controllerDoc;
				else {
					// edit() call on one controller document
					signerDoc = document.getControllerDocument(document.getControllers().get(0));
					signerDoc.getMetadata().setStore(document.getMetadata().getStore());
				}
			}

			DIDURL signKey = signerDoc.getDefaultPublicKeyId();

			try {
				String json = document.serialize(true);
				String sig = document.sign(signKey, storepass, json.getBytes());
				Proof proof = new Proof(signKey, sig);
				document.addProof(proof);
			} catch (InvalidKeyException ignore) {
				log.error("INTERNAL - Sealing document", ignore);
			} catch (DIDSyntaxException e) {
				// should never happen
				// re-throw it after up-cast
				throw (MalformedDocumentException)e;
			}

			// Invalidate builder
			DIDDocument doc = document;
			this.document = null;

			return doc;
		}
	}
}
