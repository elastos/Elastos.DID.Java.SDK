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
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;

import org.elastos.did.crypto.Base58;
import org.elastos.did.crypto.Base64;
import org.elastos.did.crypto.EcdsaSigner;
import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.DIDBackendException;
import org.elastos.did.exception.DIDNotFoundException;
import org.elastos.did.exception.DIDObjectAlreadyExistException;
import org.elastos.did.exception.DIDObjectNotExistException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.MalformedCredentialException;
import org.elastos.did.exception.MalformedDIDException;
import org.elastos.did.exception.MalformedDocumentException;
import org.elastos.did.jwt.JwtBuilder;
import org.elastos.did.jwt.JwtParserBuilder;
import org.elastos.did.jwt.KeyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.digests.SHA256Digest;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
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

	private Map<DIDURL, PublicKey> publicKeys;
	public PublicKey defaultPublicKey;

	@JsonProperty(PUBLICKEY)
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
	@JsonProperty(PROOF)
	@JsonInclude(Include.NON_NULL)
	private Proof proof;

	private DIDMetadata metadata;

	private static final Logger log = LoggerFactory.getLogger(DIDDocument.class);

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
	public static class Proof {
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

	/**
	 * Copy constructor.
	 *
	 * @param doc the document be copied
	 */
	protected DIDDocument(DIDDocument doc) {
		this.subject = doc.subject;
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
		this.proof = doc.proof;
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

	private <K, V extends DIDEntry> void removeEntry(Map<K, V> entries, K id) {
		if (entries == null || entries.isEmpty() || !entries.containsKey(id))
			throw new DIDObjectNotExistException(id.toString() + " not exists.");

		entries.remove(id);
	}

	/**
	 * Get subject of DIDDocument.
	 *
	 * @return the DID object
	 */
	public DID getSubject() {
		return subject;
	}

	/**
	 * Get the count of public keys.
	 *
	 * @return the count
	 */
	public int getPublicKeyCount() {
		return getEntryCount(publicKeys);
	}

	/**
	 * Get the public keys array.
	 *
	 * @return the PublicKey array
	 */
	public List<PublicKey> getPublicKeys() {
		return getEntries(publicKeys);
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

		return getEntries(publicKeys, (v) -> {
			if (id != null && !v.getId().equals(id))
				return false;

			if (type != null && !v.getType().equals(type))
				return false;

			return true;
		});
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

		return getEntry(publicKeys, id);
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

		return getEntry(publicKeys, id) != null;
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

		if (getEntry(publicKeys, id) == null)
			return false;

		if (!getMetadata().attachedStore())
			return false;

		return getMetadata().getStore().containsPrivateKey(getSubject(), id);
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
	 * Get default key of did document.
	 *
	 * @return the default key id
	 */
	public DIDURL getDefaultPublicKey() {
		return defaultPublicKey.getId();
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
		if (storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		if (!getMetadata().attachedStore())
			throw new DIDStoreException("Not attached with a DID store.");

		HDKey key = HDKey.deserialize(getMetadata().getStore().loadPrivateKey(
				getSubject(), getDefaultPublicKey(), storepass));

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
				getSubject(), getDefaultPublicKey(), storepass));

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
		return getEntryCount(publicKeys,
				(v) -> ((PublicKey)v).isAuthenticationKey());
	}

	/**
	 * Get the authentication key array.
	 *
	 * @return the matched authentication key array
	 */
	public List<PublicKey> getAuthenticationKeys() {
		return getEntries(publicKeys,
				(v) -> ((PublicKey)v).isAuthenticationKey());
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

		return getEntries(publicKeys, (v) -> {
			if (!((PublicKey)v).isAuthenticationKey())
				return false;

			if (id != null && !v.getId().equals(id))
				return false;

			if (type != null && !v.getType().equals(type))
				return false;

			return true;
		});
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

		PublicKey pk = getEntry(publicKeys, id);
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
		return getEntryCount(publicKeys,
				(v) -> ((PublicKey)v).isAuthorizationKey());
	}

	/**
	 * Get the authorization key array.
	 *
	 * @return the  array
	 */
	public List<PublicKey> getAuthorizationKeys() {
		return getEntries(publicKeys,
				(v) -> ((PublicKey)v).isAuthorizationKey());
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

		return getEntries(publicKeys, (v) -> {
			if (!((PublicKey)v).isAuthorizationKey())
				return false;

			if (id != null && !v.getId().equals(id))
				return false;

			if (type != null && !v.getType().equals(type))
				return false;

			return true;
		});
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

		PublicKey pk = getEntry(publicKeys, id);
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
	 * Get Proof object from did document.
	 *
	 * @return the Proof object
	 */
	public Proof getProof() {
		return proof;
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
			sanitizePublickKey();
			sanitizeCredential();
			sanitizeService();
		}

		if (publicKeys == null || publicKeys.isEmpty())
			throw new MalformedDocumentException("No public key.");

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

		if (defaultPublicKey == null)
			throw new MalformedDocumentException("Missing default public key.");

		if (_authorizations.size() == 0)
			this._authorizations = null;

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
			if (proof == null)
				throw new MalformedDocumentException("Missing document proof");

			if (proof.getCreator() == null) {
				proof.creator = defaultPublicKey.getId();
			} else {
				if (proof.getCreator().getDid() == null)
					proof.getCreator().setDid(getSubject());
			}
		}
	}

	private void sanitizePublickKey() throws MalformedDocumentException {
		if (_publickeys == null || _publickeys.size() == 0)
			throw new MalformedDocumentException("No publickey.");

		Map<DIDURL, PublicKey> pks = new TreeMap<DIDURL, PublicKey>();
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

		this.publicKeys = pks;
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
		// Document should signed(only) by default public key.
		if (!proof.getCreator().equals(getDefaultPublicKey()))
			return false;

		// Unsupported public key type;
		if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE))
			return false;

		DIDDocument doc = new DIDDocument(this);
		doc.proof = null;
		String json;
		try {
			json = doc.serialize(true);
		} catch (DIDSyntaxException ignore) {
			// Should never happen
			log.error("INTERNAL - Serialize document", ignore);
			return false;
		}
		return verify(proof.getCreator(), proof.getSignature(), json.getBytes());
	}

	/**
	 * Judge whether the did doucment is deactivated or not.
	 *
	 * @return the returned value is true if the did document is genuine;
	 *         the returned value is false if the did document is not genuine.
	 */
	public boolean isDeactivated() {
		return getMetadata().isDeactivated();
	}

	/**
	 * Judge whether the did document is valid or not.
	 *
	 * @return the returned value is true if the did document is valid;
	 *         the returned value is false if the did document is not valid.
	 */
	public boolean isValid() {
		return !isDeactivated() && !isExpired() && isGenuine();
	}

	protected DIDDocument copy() {
		DIDDocument doc = new DIDDocument(subject);

		doc.publicKeys = new TreeMap<DIDURL, PublicKey>(publicKeys);
		doc.defaultPublicKey = this.defaultPublicKey;

		if (credentials != null)
			doc.credentials = new TreeMap<DIDURL, VerifiableCredential>(credentials);

		if (services != null)
			doc.services = new TreeMap<DIDURL, Service>(services);

		doc.expires = expires;

		DIDMetadata metadata = getMetadata().clone();
		metadata.clearLastModified();
		doc.setMetadata(metadata);

		return doc;
	}

	/**
	 * Get DID Document Builder object.
	 *
	 * @return the Builder object
	 */
	public Builder edit() {
		return new Builder(copy());
	}

	/**
	 * Sign the data by the specified key.
	 *
	 * @param id the key id
	 * @param storepass the password for DIDStore
	 * @param data the data be signed
	 * @return the signature string
	 * @throws DIDStoreException there is no DIDStore to get private key.
	 */
	public String sign(DIDURL id, String storepass, byte[] ... data)
			throws DIDStoreException {
		if (id == null || data == null || data.length == 0 ||
				storepass == null || storepass.isEmpty())
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
	 * @throws DIDStoreException there is no DIDStore to get private key.
	 */
	public String sign(String id, String storepass, byte[] ... data)
			throws DIDStoreException {
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
		DIDURL key = getDefaultPublicKey();
		return sign(key, storepass, data);
	}

	/**
	 * Sign the digest data by the specified key.
	 *
	 * @param id the key id
	 * @param storepass the password for DIDStore
	 * @param digest the digest data to be signed
	 * @return the signature string
	 * @throws DIDStoreException there is no DIDStore to get private key.
	 */
	public String signDigest(DIDURL id, String storepass, byte[] digest)
			throws DIDStoreException {
		if (id == null || digest == null || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		if (!getMetadata().attachedStore())
			throw new DIDStoreException("Not attached with a DID store.");

		return getMetadata().getStore().sign(getSubject(), id, storepass, digest);
	}

	/**
	 * Sign the digest data by the specified key.
	 *
	 * @param id the key id string
	 * @param storepass the password for DIDStore
	 * @param digest the digest data to be signed
	 * @return the signature string
	 * @throws DIDStoreException there is no DIDStore to get private key.
	 */
	public String signDigest(String id, String storepass, byte[] digest)
			throws DIDStoreException {
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
		DIDURL key = getDefaultPublicKey();
		return signDigest(key, storepass, digest);
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
		if (id == null || signature == null || signature.isEmpty() ||
				data == null || data.length == 0)
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
		DIDURL key = getDefaultPublicKey();
		return verify(key, signature, data);
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
		if (id == null || signature == null || signature.isEmpty() || digest == null)
			throw new IllegalArgumentException();

		PublicKey pk = getPublicKey(id);
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
		DIDURL key = getDefaultPublicKey();
		return verifyDigest(key, signature, digest);
	}

	public JwtBuilder jwtBuilder() {
		JwtBuilder builder = new JwtBuilder(getSubject().toString(), new KeyProvider() {

			@Override
			public java.security.PublicKey getPublicKey(String id)
					throws InvalidKeyException {
				DIDURL _id = id == null ? getDefaultPublicKey() :
					new DIDURL(getSubject(), id);

				return getKeyPair(_id).getPublic();
			}

			@Override
			public PrivateKey getPrivateKey(String id, String storepass)
					throws InvalidKeyException, DIDStoreException {
				DIDURL _id = id == null ? getDefaultPublicKey() :
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
				DIDURL _id = id == null ? getDefaultPublicKey() :
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
		 * Constructs DID Document Builder with given DID Document.
		 *
		 * @param doc the DID Document object
		 */
		protected Builder(DIDDocument doc) {
			this.document = doc;
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

	        PublicKey pk = document.getPublicKey(id);
	        if (pk == null)
	            throw new DIDObjectNotExistException("PublicKey id '"
	                    + id + "' not exist.");

	        // Can not remove default public key
	        if (document.getDefaultPublicKey().equals(id))
	            throw new UnsupportedOperationException(
	                    "Cannot remove the default PublicKey.");

	        if (!force) {
	            if (pk.isAuthenticationKey() || pk.isAuthorizationKey())
	                throw new UnsupportedOperationException("Key has references.");
	        }

	        document.removeEntry(document.publicKeys, id);
	        try {
	        	// TODO: should delete the loosed private key when store the document
	            if (document.getMetadata().attachedStore())
	                document.getMetadata().getStore().deletePrivateKey(getSubject(), id);
	        } catch (DIDStoreException ignore) {
	            log.error("INTERNAL - Remove private key", ignore);
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

	        PublicKey key = document.getPublicKey(id);
	        if (key == null)
	            throw new DIDObjectNotExistException("PublicKey '" + id + "' not exists.");

	        // Check the controller is current DID subject
	        if (!key.getController().equals(getSubject()))
	            throw new UnsupportedOperationException("Key cannot used for authentication.");

	        key.setAuthenticationKey(true);

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

	        PublicKey pk = document.getPublicKey(id);
	        if (pk == null)
	            throw new DIDObjectNotExistException("PublicKey id '"
	                    + id + "' not exist.");

	        if (!pk.isAuthenticationKey())
	            throw new DIDObjectNotExistException("PublicKey id '"
	                    + id + "' not an authentication key.");

	        // Can not remove default public key
	        if (document.getDefaultPublicKey().equals(id))
	            throw new UnsupportedOperationException(
	                    "Cannot remove the default PublicKey from authentication.");

	        pk.setAuthenticationKey(false);

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

	        PublicKey key = document.getPublicKey(id);
	        if (key == null)
	            throw new DIDObjectNotExistException("PublicKey '" + id + "' not exists.");

	        // Can not authorize to self
	        if (key.getController().equals(getSubject()))
	            throw new UnsupportedOperationException("Key cannot used for authorization.");

	        key.setAuthorizationKey(true);

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
				throws DIDResolveException, InvalidKeyException {
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
				key = controllerDoc.getDefaultPublicKey();

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
				throws DIDResolveException, InvalidKeyException {
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
				throws DIDResolveException, DIDBackendException, InvalidKeyException {
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
				throws DIDResolveException, DIDBackendException, InvalidKeyException {
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

	        PublicKey pk = document.getPublicKey(id);
	        if (pk == null)
	            throw new DIDObjectNotExistException("PublicKey id '"
	                    + id + "' not exist.");

	        if (!pk.isAuthorizationKey())
	            throw new DIDObjectNotExistException("PublicKey id '"
	                    + id + "' not an authorization key.");

	        pk.setAuthorizationKey(false);

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

			document.removeEntry(document.credentials, id);

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

			document.removeEntry(document.services, id);

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
			return this;
		}

		/**
		 * Seal the document object, attach the generated proof to the
		 * document.
		 *
		 * @param storepass the password for DIDStore
		 * @return the DIDDocument object
		 * @throws MalformedDocumentException if the DIDDocument is malformed
		 * @throws DIDStoreException if an error occurs when access DID store
		 */
		public DIDDocument seal(String storepass)
				throws MalformedDocumentException, DIDStoreException {
			if (document == null)
				throw new IllegalStateException("Document already sealed.");

			if (storepass == null || storepass.isEmpty())
				throw new IllegalArgumentException();

			if (document.getExpires() == null)
				setDefaultExpires();

			document.sanitize(false);

			DIDURL signKey = document.getDefaultPublicKey();
			String json;
			try {
				json = document.serialize(true);
			} catch (DIDSyntaxException e) {
				// should never happen
				// re-throw it after up-cast
				throw (MalformedDocumentException)e;
			}

			String sig = document.sign(signKey, storepass, json.getBytes());
			Proof proof = new Proof(signKey, sig);
			document.proof = proof;

			// Invalidate builder
			DIDDocument doc = document;
			this.document = null;

			return doc;
		}
	}
}
