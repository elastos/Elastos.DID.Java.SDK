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
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import org.elastos.did.crypto.Base58;
import org.elastos.did.crypto.Base64;
import org.elastos.did.crypto.EcdsaSigner;
import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.AlreadySealedException;
import org.elastos.did.exception.AlreadySignedException;
import org.elastos.did.exception.CanNotRemoveEffectiveControllerException;
import org.elastos.did.exception.DIDAlreadyExistException;
import org.elastos.did.exception.DIDBackendException;
import org.elastos.did.exception.DIDControllersChangedException;
import org.elastos.did.exception.DIDDeactivatedException;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDExpiredException;
import org.elastos.did.exception.DIDNotFoundException;
import org.elastos.did.exception.DIDNotGenuineException;
import org.elastos.did.exception.DIDNotUpToDateException;
import org.elastos.did.exception.DIDObjectAlreadyExistException;
import org.elastos.did.exception.DIDObjectHasReferenceException;
import org.elastos.did.exception.DIDObjectNotExistException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.IllegalUsageException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.MalformedCredentialException;
import org.elastos.did.exception.MalformedDocumentException;
import org.elastos.did.exception.NoEffectiveControllerException;
import org.elastos.did.exception.NotAttachedWithStoreException;
import org.elastos.did.exception.NotControllerException;
import org.elastos.did.exception.NotCustomizedDIDException;
import org.elastos.did.exception.NotPrimitiveDIDException;
import org.elastos.did.exception.UnknownInternalException;
import org.elastos.did.jwt.JwtBuilder;
import org.elastos.did.jwt.JwtParserBuilder;
import org.elastos.did.jwt.KeyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.digests.SHA256Digest;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFilter;
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
import com.fasterxml.jackson.databind.ser.PropertyFilter;
import com.fasterxml.jackson.databind.ser.PropertyWriter;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

/**
 * DID documents contain information associated with a DID.
 * They typically express verification methods, such as cryptographic
 * public keys, and services relevant to interactions with the DID subject.
 *
 * <p>
 * The generic properties supported in a DID document are specified by the
 * <a href="https://github.com/elastos/Elastos.DID.Method">Elastos DID Method Specification</a>.
 * </p>
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
public class DIDDocument extends DIDEntity<DIDDocument> {
	protected final static String ID = "id";
	protected final static String PUBLICKEY = "publicKey";
	protected final static String TYPE = "type";
	protected final static String CONTROLLER = "controller";
	protected final static String MULTI_SIGNATURE = "multisig";
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
	@JsonInclude(Include.NON_EMPTY)
	private List<DID> controllers;

	@JsonProperty(MULTI_SIGNATURE)
	@JsonInclude(Include.NON_NULL)
	MultiSignature multisig;

	@JsonProperty(PUBLICKEY)
	@JsonInclude(Include.NON_EMPTY)
	private List<PublicKey> _publickeys;

	@JsonProperty(AUTHENTICATION)
	@JsonInclude(Include.NON_EMPTY)
	private List<PublicKeyReference> _authentications;

	@JsonProperty(AUTHORIZATION)
	@JsonInclude(Include.NON_EMPTY)
	private List<PublicKeyReference> _authorizations;

	@JsonProperty(VERIFIABLE_CREDENTIAL)
	@JsonInclude(Include.NON_EMPTY)
	private List<VerifiableCredential> _credentials;

	@JsonProperty(SERVICE)
	@JsonInclude(Include.NON_EMPTY)
	private List<Service> _services;

	@JsonProperty(EXPIRES)
	@JsonInclude(Include.NON_NULL)
	private Date expires;

	@JsonProperty(PROOF)
	@JsonInclude(Include.NON_EMPTY)
	@JsonFormat(with = {JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY,
			JsonFormat.Feature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED})
	private List<Proof> _proofs;

	private Map<DID, DIDDocument> controllerDocs;
	private Map<DIDURL, PublicKey> publicKeys;
	private Map<DIDURL, VerifiableCredential> credentials;
	private Map<DIDURL, Service> services;
	private HashMap<DID, Proof> proofs;

	private DID effectiveController;
	private PublicKey defaultPublicKey;

	private DIDMetadata metadata;

	private static final Logger log = LoggerFactory.getLogger(DIDDocument.class);

	/**
	 * MultiSignature is a digital signature scheme which allows a group of
	 * users to sign a single document.
	 */
	public static class MultiSignature {
		private int m;
		private int n;

		/**
		 * Create a MultiSignature instance with given signature specification.
		 *
		 * <p>
		 * The MultiSignature can be of the m-of-n type where any m private
		 * keys out of a possible n are required to sign/verify the signature.
		 * </p>
		 *
		 * @param m m required keys
		 * @param n n possible keys
		 */
		public MultiSignature(int m, int n) {
			apply(m, n);
		}

		/**
		 * Copy constructor.
		 *
		 * @param ms the source MultiSignature object
		 */
		private MultiSignature(MultiSignature ms) {
			apply(ms.m, ms.n);
		}

		/**
		 * Create a MultiSignature instance with given signature specification.
		 *
		 * @param mOfN the string format m-of-n(m:n)
		 */
		@JsonCreator
		public MultiSignature(String mOfN) {
			if (mOfN == null || mOfN.isEmpty())
				throw new IllegalArgumentException("Invalid multisig spec");

			String[] mn = mOfN.split(":");
			if (mn == null || mn.length != 2)
				throw new IllegalArgumentException("Invalid multisig spec");

			apply(Integer.valueOf(mn[0]), Integer.valueOf(mn[1]));
		}

		private void apply(int m, int n) {
			checkArgument(n > 1, "Invalid multisig spec: n should > 1");
			checkArgument(m > 0 && m <= n,  "Invalid multisig spec: m should > 0 and <= n");

			this.m = m;
			this.n = n;
		}

		/**
		 * Get the m of requested signatures.
		 *
		 * @return m
		 */
		public int m() {
			return m;
		}

		/**
		 * Get the n of possible signatures.
		 *
		 * @return m
		 */
		public int n() {
			return n;
		}

		/**
		 * Compares this MultiSignature to the specified object.
		 * The result is true if and only if the argument is not null and
		 * is a MultiSignature object that represents the same schema.
		 *
		 * @param obj the object to compare this MultiSignature against
		 * @return true if the given object represents a MultiSignature
		 * 		   equivalent to this object, false otherwise
		 */
		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;

			if (obj instanceof MultiSignature) {
				MultiSignature multisig = (MultiSignature)obj;
				return m == multisig.m && n == multisig.n;
			}

			return false;
		}

		/**
		 * Return the string representation of this MultiSignature object.
		 *
		 * @return a string representation of this MultiSignature object
		 */
		@Override
		@JsonValue
		public String toString() {
			return String.format("%d:%d", m, n);
		}
	}

	/**
	 * PublicKey is used for digital signatures, encryption and
	 * other cryptographic operations, which are the basis for purposes such as
	 * authentication or establishing secure communication with service endpoints.
	 */
	@JsonPropertyOrder({ ID, TYPE, CONTROLLER, PUBLICKEY_BASE58 })
	@JsonFilter("publicKeyFilter")
	public static class PublicKey implements DIDObject, Comparable<PublicKey> {
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
		 * Constructs a PublicKey instance with the given values.
		 *
		 * @param id the id of the PublicKey
		 * @param type the key type, default type is "ECDSAsecp256r1"
		 * @param controller the DID who holds the private key
		 * @param keyBase58 the base58 encoded public key
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
		 * Get the PublicKey id.
		 *
		 * @return the key id
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
		 * Get the controller of this PublicKey.
		 *
		 * @return the controller's DID
		 */
		public DID getController() {
			return controller;
		}

		/**
		 * Get the base58 encoded public key string.
		 *
		 * @return the base58 encoded public key
		 */
		public String getPublicKeyBase58() {
			return keyBase58;
		}

		/**
		 * Get the raw binary public key bytes.
		 *
		 * @return a bytes array of binary public key
		 */
		public byte[] getPublicKeyBytes() {
			return Base58.decode(keyBase58);
		}

		/**
		 * Check if the key is an authentication key.
		 *
		 * @return if true if is an authentication key, false otherwise
		 */
		public boolean isAuthenticationKey() {
			return authenticationKey;
		}

		/**
		 * Set this PublicKey as an authentication key or not.
		 *
		 * @param authenticationKey true set this key as an authentication key;
		 * 		  false remove this key from authentication keys
		 */
		private void setAuthenticationKey(boolean authenticationKey) {
			this.authenticationKey = authenticationKey;
		}

		/**
		 * Check if the key is an authorization key.
		 *
		 * @return if true if is an authorization key, false otherwise
		 */
		public boolean isAuthorizationKey() {
			return authorizationKey;
		}

		/**
		 * Set this PublicKey as an authorization key or not.
		 *
		 * @param authenticationKey true set this key as an authorization key;
		 * 		  false remove this key from authorization keys
		 */
		private void setAuthorizationKey(boolean authorizationKey) {
			this.authorizationKey = authorizationKey;
		}

		/**
		 * Compares this PublicKey to the specified object.
		 * The result is true if and only if the argument is not null and
		 * is a PublicKey object that represents the same key.
		 *
		 * @param obj the object to compare this PublicKey against
		 * @return true if the given object represents a PublicKey
		 * 		   equivalent to this object, false otherwise
		 */
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

		/**
		 * Compares this PublicKey with the specified PublicKey.
		 *
		 * @param key PublicKey to which this PublicKey is to be compared
		 * @return -1, 0 or 1 as this PublicKey is less than, equal to,
		 * 		   or greater than key
		 */
		@Override
		public int compareTo(PublicKey key) {
			int rc = id.compareTo(key.id);

			if (rc != 0)
				return rc;
			else
				rc = keyBase58.compareTo(key.keyBase58);

			if (rc != 0)
				return rc;
			else
				rc = type.compareTo(key.type);

			if (rc != 0)
				return rc;
			else
				return controller.compareTo(key.controller);
		}

		static PropertyFilter getFilter() {
			return new DIDPropertyFilter() {
				@Override
				protected boolean include(PropertyWriter writer, Object pojo, SerializeContext context) {
					if (context.isNormalized())
						return true;

					PublicKey pk = (PublicKey)pojo;
					switch (writer.getName()) {
					case TYPE:
						return !(pk.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE));

					case CONTROLLER:
						return !(pk.getController().equals(context.getDid()));

					default:
						return true;
					}
				}
			};
		}
	}

	@JsonSerialize(using = PublicKeyReference.Serializer.class)
	@JsonDeserialize(using = PublicKeyReference.Deserializer.class)
	private static class PublicKeyReference implements Comparable<PublicKeyReference> {
		private DIDURL id;
		private PublicKey key;

		protected PublicKeyReference(DIDURL id) {
			this.id = id;
			this.key = null;
		}

		protected PublicKeyReference(PublicKey key) {
			this.id = key.getId();
			this.key = key;
		}

		public boolean isVirtual() {
			return key == null;
		}

		public DIDURL getId() {
			return id;
		}

		public PublicKey getPublicKey() {
			return key;
		}

		protected void update(PublicKey key) {
			checkArgument(key != null && key.getId().equals(id));

			this.id = key.getId();
			this.key = key;
		}

		@Override
		public int compareTo(PublicKeyReference ref) {
			if (key != null && ref.key != null)
				return key.compareTo(ref.key);
			else
				return id.compareTo(ref.id);
		}

		static class Serializer extends StdSerializer<PublicKeyReference> {
			private static final long serialVersionUID = -6934608221544406405L;

			@SuppressWarnings("unused")
			public Serializer() {
				this(null);
			}

			public Serializer(Class<PublicKeyReference> t) {
				super(t);
			}

			@Override
			public void serialize(PublicKeyReference keyRef, JsonGenerator gen,
					SerializerProvider provider) throws IOException {
				gen.writeObject(keyRef.getId());
			}
		}

		static class Deserializer extends StdDeserializer<PublicKeyReference> {
			private static final long serialVersionUID = -4252894239212420927L;

			@SuppressWarnings("unused")
			public Deserializer() {
				this(null);
			}

			public Deserializer(Class<?> t) {
				super(t);
			}

			@Override
			public PublicKeyReference deserialize(JsonParser p, DeserializationContext ctxt)
					throws IOException, JsonProcessingException {
				JsonToken token = p.getCurrentToken();
				if (token.equals(JsonToken.VALUE_STRING)) {
					DIDURL id = p.readValueAs(DIDURL.class);
					return new PublicKeyReference(id);
				} else if (token.equals(JsonToken.START_OBJECT)) {
					PublicKey key = p.readValueAs(PublicKey.class);
					return new PublicKeyReference(key);
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
	public static class Service implements DIDObject {
		@JsonProperty(ID)
		private DIDURL id;
		@JsonProperty(TYPE)
		private String type;
		@JsonProperty(SERVICE_ENDPOINT)
		private String endpoint;

		private Map<String, Object> properties;

		/**
		 * Create a Service object with given values.
		 *
		 * @param id the service id
		 * @param type the service type
		 * @param endpoint the service endpoint, could be URL or any application defined address
		 * @param properties a map for the extra properties
		 */
		protected Service(DIDURL id, String type, String endpoint,
				Map<String, Object> properties) {
			this.id = id;
			this.type = type;
			this.endpoint = endpoint;

			if (properties != null && !properties.isEmpty()) {
				this.properties = new TreeMap<String, Object>(properties);
				this.properties.remove(ID);
				this.properties.remove(TYPE);
				this.properties.remove(SERVICE_ENDPOINT);
			}
		}

		/**
		 * Create a Service object with given values.
		 *
		 * @param id the service id
		 * @param type the service type
		 * @param endpoint the service endpoint, could be URL or any application defined address
		 */
		@JsonCreator
		protected Service(@JsonProperty(value = ID, required = true) DIDURL id,
				@JsonProperty(value = TYPE, required = true) String type,
				@JsonProperty(value = SERVICE_ENDPOINT, required = true) String endpoint) {
			this(id, type, endpoint, null);
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
		 * Get the service endpoint.
		 *
		 * @return the service endpoint
		 */
		public String getServiceEndpoint() {
			return endpoint;
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
			if (name.equals(ID) || name.equals(TYPE) || name.equals(SERVICE_ENDPOINT))
				return;

			if (properties == null)
				properties = new TreeMap<String, Object>();

			properties.put(name, value);
		}

		/**
		 * Get the extra properties of the service.
		 *
		 * @return a map object contains the extra properties
		 */
		public Map<String, Object> getProperties() {
			// TODO: make it unmodifiable recursively
			 return Collections.unmodifiableMap(properties != null ?
					 properties : Collections.emptyMap());
		}
	}

	/**
	 * The Proof class represents the proof content of DID Document.
	 */
	@JsonPropertyOrder({ TYPE, CREATED, CREATOR, SIGNATURE_VALUE })
	@JsonFilter("didDocumentProofFilter")
	public static class Proof implements Comparable<Proof> {
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
		 * Constructs a Proof object with the given values.
		 *
		 * @param type the type of Proof
		 * @param created the create time stamp
		 * @param creator the key that sign this proof
		 * @param signature the signature string
		 */
		@JsonCreator
		protected Proof(@JsonProperty(value = TYPE) String type,
				@JsonProperty(value = CREATED, required = true) Date created,
				@JsonProperty(value = CREATOR) DIDURL creator,
				@JsonProperty(value = SIGNATURE_VALUE, required = true) String signature) {
			this.type = type != null ? type : Constants.DEFAULT_PUBLICKEY_TYPE;
			this.created = created == null ? null : new Date(created.getTime() / 1000 * 1000);
			this.creator = creator;
			this.signature = signature;
		}

		/**
		 * Constructs a Proof object with the given values.
		 *
		 * @param creator the key that sign this proof
		 * @param signature the signature string
		 */
		protected Proof(DIDURL creator, String signature) {
			this(null, Calendar.getInstance(Constants.UTC).getTime(), creator, signature);
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
		 * Get the create time of this proof object.
		 *
		 * @return the create time stamp
		 */
		public Date getCreated() {
			return created;
		}

		/**
		 * Get the key id that sign this proof object
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

		/**
		 * Compares this Proof with the specified Proof object.
		 *
		 * @param proof Proof to which this Proof is to be compared
		 * @return -1, 0 or 1 as this Proof is less than, equal to,
		 * 		   or greater than proof
		 */
		@Override
		public int compareTo(Proof proof) {
			int rc = (int)(this.created.getTime() - proof.created.getTime());
			if (rc == 0)
				rc = this.creator.compareTo(proof.creator);
			return rc;
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
	 * Construct a new DIDDocument object with given subject.
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
	 * @param withProof copy with the proof or not
	 */
	private DIDDocument(DIDDocument doc, boolean withProof) {
		this.subject = doc.subject;
		this.controllers = doc.controllers;
		this.controllerDocs = doc.controllerDocs;
		this.effectiveController = doc.effectiveController;
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
		if (withProof) {
			this.proofs = doc.proofs;
			this._proofs = doc._proofs;
		}
		this.metadata = doc.metadata;
	}

	/**
	 * Get subject of this DIDDocument.
	 *
	 * @return the DID object
	 */
	public DID getSubject() {
		return subject;
	}

	private DIDURL canonicalId(String id) {
		return DIDURL.valueOf(getSubject(), id);
	}

	private DIDURL canonicalId(DIDURL id) {
		if (id == null || id.getDid() != null)
			return id;

		return new DIDURL(getSubject(), id);
	}

	private void checkAttachedStore() throws NotAttachedWithStoreException {
		if (!getMetadata().attachedStore())
			throw new NotAttachedWithStoreException();
	}

	private void checkIsPrimitive() throws NotPrimitiveDIDException {
		if (isCustomizedDid())
			throw new NotPrimitiveDIDException(getSubject().toString());
	}

	private void checkIsCustomized() throws NotCustomizedDIDException {
		if (!isCustomizedDid())
			throw new NotCustomizedDIDException(getSubject().toString());
	}

	private void checkHasEffectiveController() throws NoEffectiveControllerException {
		if (getEffectiveController() == null)
			throw new NoEffectiveControllerException(getSubject().toString());
	}

	public boolean isCustomizedDid() {
		return defaultPublicKey == null;
	}

	/**
	 * Get contoller's DIDs.
	 *
	 * @return the Controllers DID list or empty list if no controller
	 */
	public List<DID> getControllers() {
		return Collections.unmodifiableList(controllers);
	}

	/**
	 * Get controller count.
	 *
	 * @return the controller count
	 */
	public int getControllerCount() {
		return controllers.size();
	}

	/**
	 * Get contoller's DID.
	 *
	 * @return the Controller's DID if only has one controller, other wise null
	 */
	protected DID getController() {
		return controllers.size() == 1 ? controllers.get(0) : null;
	}

	/**
	 * Check if current DID has controller.
	 *
	 * @return true if has, false otherwise
	 */
	public boolean hasController() {
		return !controllers.isEmpty();
	}

	/**
	 * Check if current DID has specific controller.
	 *
	 * @param did the controller's DID that to be test
	 * @return true if has, otherwise false
	 */
	public boolean hasController(DID did) {
		return controllers.contains(did);
	}

	/**
	 * Get the specific controller's DID document.
	 *
	 * @param did the controller's DID
	 * @return the DIDDocument object or null if no controller
	 */
	public DIDDocument getControllerDocument(DID did) {
		return controllerDocs.get(did);
	}

	/**
	 * Get the current effective controller for the customized DIDDocument.
	 *
	 * @return the effective controller's DID or null if not set
	 */
	public DID getEffectiveController() {
		return effectiveController;
	}

	/**
	 * Get the current effective controller's document for the
	 * customized DIDDocument.
	 *
	 * @return the effective controller's document or null if not set
	 */
	protected DIDDocument getEffectiveControllerDocument() {
		return effectiveController == null ? null : getControllerDocument(effectiveController);
	}

	/**
	 * Set the current effective controller for the customized DIDDocument.
	 *
	 * @param controller the new effective controller
	 */
	public void setEffectiveController(DID controller) {
		checkIsCustomized();

		if (controller == null) {
			effectiveController = controller;
			return;
		} else {
			if (!hasController(controller))
				throw new NotControllerException("Not contoller for target DID");

			effectiveController = controller;

			// attach to the store if necessary
			DIDDocument doc = getControllerDocument(effectiveController);
			if (!doc.getMetadata().attachedStore())
				doc.getMetadata().attachStore(getMetadata().getStore());
		}
	}

	/**
	 * Check if this document is a multisig document.
	 *
	 * @return true if the document is a multisig document, false otherwise
	 */
	public boolean isMultiSignature() {
		return multisig != null;
	}

	/**
	 * Get the multisig specification of this document.
	 *
	 * @return the MultiSignature specification
	 */
	public MultiSignature getMultiSignature() {
		return multisig;
	}

	/**
	 * Get the number of the public keys.
	 *
	 * @return the number of the public keys
	 */
	public int getPublicKeyCount() {
		int count = publicKeys.size();

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values())
				count += doc.getAuthenticationKeyCount();
		}

		return count;
	}

	/**
	 * Get all the public keys.
	 *
	 * @return a array of PublicKey object
	 */
	public List<PublicKey> getPublicKeys() {
		List<PublicKey> pks = new ArrayList<PublicKey>(publicKeys.values());

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values())
				pks.addAll(doc.getAuthenticationKeys());
		}

		return Collections.unmodifiableList(pks);
	}

	/**
	 * Select the public keys by the specified key id or key type.
	 *
	 * @param id the optional key id
	 * @param type the optional key type
	 * @return an array of the matched public keys
	 */
	public List<PublicKey> selectPublicKeys(DIDURL id, String type) {
		checkArgument(id != null || type != null, "Invalid select args");

		id = canonicalId(id);

		List<PublicKey> pks = new ArrayList<PublicKey>(publicKeys.size());
		for (PublicKey pk : publicKeys.values()) {
			if (id != null && !pk.getId().equals(id))
				continue;

			if (type != null && !pk.getType().equals(type))
				continue;

			pks.add(pk);
		}

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values())
				pks.addAll(doc.selectAuthenticationKeys(id, type));
		}

		return Collections.unmodifiableList(pks);

	}

	/**
	 * Select the public keys by the specified key id or key type.
	 *
	 * @param id the optional key id
	 * @param type the optional key type
	 * @return an array of the matched public keys
	 */
	public List<PublicKey> selectPublicKeys(String id, String type) {
		return selectPublicKeys(canonicalId(id), type);
	}

	/**
	 * Get the specific public key.
	 *
	 * @param id the key id
	 * @return the PublicKey object
	 */
	public PublicKey getPublicKey(String id) {
		return getPublicKey(canonicalId(id));
	}

	/**
	 * Get the specific public key.
	 *
	 * @param id the key id
	 * @return the PublicKey object
	 */
	public PublicKey getPublicKey(DIDURL id) {
		checkArgument(id != null, "Invalid publicKey id");

		id = canonicalId(id);
		PublicKey pk = publicKeys.get(id);
		if (pk == null && hasController()) {
			DIDDocument doc = getControllerDocument(id.getDid());
			if (doc != null)
				pk = doc.getAuthenticationKey(id);
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
		return getPublicKey(id) != null;
	}

	/**
	 * Check if the specified public key exists.
	 *
	 * @param id the key id
	 * @return the key exists or not
	 */
	public boolean hasPublicKey(String id) {
		return hasPublicKey(canonicalId(id));
	}

	/**
	 * Check if the specified private key exists.
	 *
	 * @param id the key id
	 * @return the key exists or not
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean hasPrivateKey(DIDURL id) throws DIDStoreException {
		checkArgument(id != null, "Invalid publicKey id");

		if (hasPublicKey(id) && getMetadata().attachedStore())
			return getMetadata().getStore().containsPrivateKey(id);
		else
			return false;
	}

	/**
	 * Check if the specified private key exists.
	 *
	 * @param id the key id
	 * @return the key exists or not
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean hasPrivateKey(String id) throws DIDStoreException {
		return hasPrivateKey(canonicalId(id));
	}

	/**
	 * Get default public key id
	 *
	 * @return the default public key id
	 */
	public DIDURL getDefaultPublicKeyId() {
		PublicKey pk = getDefaultPublicKey();
		return pk != null ? pk.getId() : null;
	}

	/**
	 * Get default public key.
	 *
	 * @return the default public key
	 */
	public PublicKey getDefaultPublicKey() {
		if (defaultPublicKey != null)
			return defaultPublicKey;

		if (effectiveController != null)
			return getControllerDocument(effectiveController).getDefaultPublicKey();

		return null;
	}

	/**
	 * Get the JCE KeyPair object for the given public key.
	 *
	 * @param id the public key id
	 * @return the JCE KeyPair object
	 */
	public KeyPair getKeyPair(DIDURL id) {
		PublicKey pk;

		if (id == null) {
			pk = getDefaultPublicKey();
			if (pk == null)
				throw new NoEffectiveControllerException(getSubject().toString());
		} else {
			pk = getPublicKey(id);
			if (pk == null)
				throw new InvalidKeyException(id.toString());
		}

		HDKey key = HDKey.deserialize(HDKey.paddingToExtendedPublicKey(
				pk.getPublicKeyBytes()));

		return key.getJCEKeyPair();
	}

	/**
	 * Get the JCE KeyPair object for the given public key.
	 *
	 * @param id the public key id
	 * @return the JCE KeyPair object
	 */
	public KeyPair getKeyPair(String id) {
		return getKeyPair(canonicalId(id));
	}

	/**
	 * Get the JCE KeyPair object for the default public key.
	 *
	 * @return the JCE KeyPair object
	 */
	public KeyPair getKeyPair() {
		return getKeyPair((DIDURL)null);
	}

	private KeyPair getKeyPair(DIDURL id, String storepass) throws DIDStoreException {
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkAttachedStore();

		if (id == null) {
			id = getDefaultPublicKeyId();
			if (id == null)
				throw new NoEffectiveControllerException(getSubject().toString());
		} else {
			if (!hasPublicKey(id))
				throw new InvalidKeyException(ID.toString());
		}

		if (!getMetadata().getStore().containsPrivateKey(id))
			throw new InvalidKeyException("No private key: " + id);

		HDKey key = HDKey.deserialize(getMetadata().getStore().loadPrivateKey(
				id, storepass));

		return key.getJCEKeyPair();
	}

	/**
	 * Derive a private key from this DID. The new private key will derive from
	 * the default private key of the this DIDDocument.
	 *
	 * @param index the derive index
	 * @param storepass the password for the DIDStore
	 * @return the extended private key format. (the real private key is
	 *         32 bytes long start from position 46)
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public String derive(int index, String storepass) throws DIDStoreException {
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkAttachedStore();
		checkIsPrimitive();

		HDKey key = HDKey.deserialize(getMetadata().getStore().loadPrivateKey(
				getDefaultPublicKeyId(), storepass));

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
	 * Derive a private key from this DID. The new private key will derive from
	 * the default private key of the this DIDDocument.
	 *
	 * @param identifier the identifier string
	 * @param securityCode the security code
	 * @param storepass the password for the DIDStore
	 * @return the extended private key format. (the real private key is
	 *         32 bytes long start from position 46)
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public String derive(String identifier, int securityCode, String storepass)
			throws DIDStoreException {
		checkArgument(identifier != null && !identifier.isEmpty(), "Invalid identifier");
		checkAttachedStore();
		checkIsPrimitive();

		HDKey key = HDKey.deserialize(getMetadata().getStore().loadPrivateKey(
				getDefaultPublicKeyId(), storepass));

		String path = mapToDerivePath(identifier, securityCode);
		return key.derive(path).serializeBase58();
	}

	/**
	 * Get the numbers of the authentication keys.
	 *
	 * @return the numbers of authentication keys
	 */
	public int getAuthenticationKeyCount() {
		int count = 0;

		for (PublicKey pk : publicKeys.values()) {
			if (pk.isAuthenticationKey())
				count++;
		}

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values())
				count += doc.getAuthenticationKeyCount();
		}

		return count;
	}

	/**
	 * Get all the authentication keys.
	 *
	 * @return an array of the authentication keys
	 */
	public List<PublicKey> getAuthenticationKeys() {
		List<PublicKey> pks = new ArrayList<PublicKey>();

		for (PublicKey pk : publicKeys.values()) {
			if (pk.isAuthenticationKey())
				pks.add(pk);
		}

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values())
				pks.addAll(doc.getAuthenticationKeys());
		}

		return Collections.unmodifiableList(pks);
	}

	/**
	 * Select the authentication keys by the specified key id or key type.
	 *
	 * @param id the optional key id
	 * @param type the optional key type
	 * @return an array of the matched authentication keys
	 */
	public List<PublicKey> selectAuthenticationKeys(DIDURL id, String type) {
		checkArgument(id != null || type != null, "Invalid select args");

		id = canonicalId(id);

		List<PublicKey> pks = new ArrayList<PublicKey>();
		for (PublicKey pk : publicKeys.values()) {
			if (!pk.isAuthenticationKey())
				continue;

			if (id != null && !pk.getId().equals(id))
				continue;

			if (type != null && !pk.getType().equals(type))
				continue;

			pks.add(pk);
		}

		if (hasController()) {
			for (DIDDocument doc : controllerDocs.values())
				pks.addAll(doc.selectAuthenticationKeys(id, type));
		}

		return Collections.unmodifiableList(pks);
	}

	/**
	 * Select the authentication keys by the specified key id or key type.
	 *
	 * @param id the optional key id
	 * @param type the optional key type
	 * @return an array of the matched authentication keys
	 */
	public List<PublicKey> selectAuthenticationKeys(String id, String type) {
		return selectAuthenticationKeys(canonicalId(id), type);
	}

	/**
	 * Get authentication key with specified key id.
	 *
	 * @param id the key id
	 * @return the matched authentication key object
	 */
	public PublicKey getAuthenticationKey(DIDURL id) {
		PublicKey pk = getPublicKey(id);
		return (pk != null && pk.isAuthenticationKey()) ? pk : null;
	}

	/**
	 * Get authentication key with specified key id.
	 *
	 * @param id the key id string
	 * @return the matched authentication key object
	 */
	public PublicKey getAuthenticationKey(String id) {
		return getAuthenticationKey(canonicalId(id));
	}

	/**
	 * Check whether the given key is authentication key.
	 *
	 * @param id the key id string
	 * @return true if the key is an authentication key, false otherwise
	 */
	public boolean isAuthenticationKey(DIDURL id) {
		return getAuthenticationKey(id) != null;
	}

	/**
	 * Check whether the given key is authentication key.
	 *
	 * @param id the key id string
	 * @return true if the key is an authentication key, false otherwise
	 */
	public boolean isAuthenticationKey(String id) {
		return isAuthenticationKey(canonicalId(id));
	}

	/**
	 * Get the numbers of the authorization keys.
	 *
	 * @return the numbers of the authorization keys
	 */
	public int getAuthorizationKeyCount() {
		int count = 0;

		for (PublicKey pk : publicKeys.values()) {
			if (pk.isAuthorizationKey())
				count++;
		}

		return count;
	}

	/**
	 * Get all the authorization keys.
	 *
	 * @return an array of authorization keys
	 */
	public List<PublicKey> getAuthorizationKeys() {
		List<PublicKey> pks = new ArrayList<PublicKey>();

		for (PublicKey pk : publicKeys.values()) {
			if (pk.isAuthorizationKey())
				pks.add(pk);
		}

		return Collections.unmodifiableList(pks);
	}

	/**
	 * Select the authorization keys by the specified key id or key type.
	 *
	 * @param id the optional key id
	 * @param type the optional key type
	 * @return an array of the matched authorization keys
	 */
	public List<PublicKey> selectAuthorizationKeys(DIDURL id, String type) {
		checkArgument(id != null || type != null, "Invalid select args");

		id = canonicalId(id);

		List<PublicKey> pks = new ArrayList<PublicKey>();
		for (PublicKey pk : publicKeys.values()) {
			if (!pk.isAuthorizationKey())
				continue;

			if (id != null && !pk.getId().equals(id))
				continue;

			if (type != null && !pk.getType().equals(type))
				continue;

			pks.add(pk);
		}

		return Collections.unmodifiableList(pks);
	}

	/**
	 * Select the authorization keys by the specified key id or key type.
	 *
	 * @param id the optional key id
	 * @param type the optional key type
	 * @return an array of the matched authorization keys
	 */
	public List<PublicKey> selectAuthorizationKeys(String id, String type) {
		return selectAuthorizationKeys(canonicalId(id), type);
	}

	/**
	 * Get the specific authorization key.
	 *
	 * @param id the key id
	 * @return the PublicKey object
	 */
	public PublicKey getAuthorizationKey(DIDURL id) {
		PublicKey pk = getPublicKey(id);
		return pk != null && pk.isAuthorizationKey() ? pk : null;
	}

	/**
	 * Get the specific authorization key.
	 *
	 * @param id the key id
	 * @return the PublicKey object
	 */
	public PublicKey getAuthorizationKey(String id) {
		return getAuthorizationKey(canonicalId(id));
	}

	/**
	 * Check whether the given key is authorization key.
	 *
	 * @param id the key id string
	 * @return true if the key is an authorization key, false otherwise
	 */
	public boolean isAuthorizationKey(DIDURL id) {
		return getAuthorizationKey(id) != null;
	}

	/**
	 * Check whether the given key is authorization key.
	 *
	 * @param id the key id string
	 * @return true if the key is an authorization key, false otherwise
	 */
	public boolean isAuthorizationKey(String id) {
		return isAuthorizationKey(canonicalId(id));
	}

	/**
	 * Get the numbers of the credentials.
	 *
	 * @return the numbers of the credentials
	 */
	public int getCredentialCount() {
		return credentials.size();
	}

	/**
	 * Get all the credential.
	 *
	 * @return an array of the credential objects
	 */
	public List<VerifiableCredential> getCredentials() {
		return Collections.unmodifiableList(_credentials);
	}

	/**
	 * Select the credentials by the specified id or type.
	 *
	 * @param id the optional credential id
	 * @param type the optional credential type
	 * @return an array of the matched credentials
	 */
	public List<VerifiableCredential> selectCredentials(DIDURL id, String type) {
		checkArgument(id != null || type != null, "Invalid select args");

		id = canonicalId(id);

		List<VerifiableCredential> vcs = new ArrayList<VerifiableCredential>();
		for (VerifiableCredential vc : credentials.values()) {
			if (id != null && !vc.getId().equals(id))
				continue;

			if (type != null && !vc.getType().contains(type))
				continue;

			vcs.add(vc);
		}

		return Collections.unmodifiableList(vcs);
	}

	/**
	 * Select the credentials by the specified id or type.
	 *
	 * @param id the optional credential id
	 * @param type the optional credential type
	 * @return an array of the matched credentials
	 */
	public List<VerifiableCredential> selectCredentials(String id, String type) {
		return selectCredentials(canonicalId(id), type);
	}

	/**
	 * Get the specific credential.
	 *
	 * @param id the credential id
	 * @return the credential object
	 */
	public VerifiableCredential getCredential(DIDURL id) {
		checkArgument(id != null, "Invalid Credential id");

		return credentials.get(canonicalId(id));
	}

	/**
	 * Get the specific credential.
	 *
	 * @param id the credential id
	 * @return the credential object
	 */
	public VerifiableCredential getCredential(String id) {
		return getCredential(canonicalId(id));
	}

	/**
	 * Get the numbers of the services.
	 *
	 * @return the numbers of the services
	 */
	public int getServiceCount() {
		return services.size();
	}

	/**
	 * Get all the services.
	 *
	 * @return an array of the services
	 */
	public List<Service> getServices() {
		return Collections.unmodifiableList(_services);
	}

	/**
	 * Select the services by the specified id or type.
	 *
	 * @param id the optional service id
	 * @param type the optional service type
	 * @return an array of the matched services
	 */
	public List<Service> selectServices(DIDURL id, String type) {
		checkArgument(id != null || type != null, "Invalid select args");

		id = canonicalId(id);

		List<Service> svcs = new ArrayList<Service>();
		for (Service svc : services.values()) {
			if (id != null && !svc.getId().equals(id))
				continue;

			if (type != null && !svc.getType().equals(type))
				continue;

			svcs.add(svc);
		};

		return Collections.unmodifiableList(svcs);
	}

	/**
	 * Select the services by the specified id or type.
	 *
	 * @param id the optional service id
	 * @param type the optional service type
	 * @return an array of the matched services
	 */
	public List<Service> selectServices(String id, String type) {
		return selectServices(canonicalId(id), type);
	}

	/**
	 * Get the specific service.
	 *
	 * @param id the service id
	 * @return the service object
	 */
	public Service getService(DIDURL id) {
		checkArgument(id != null, "Invalid service id");
		return services.get(canonicalId(id));
	}

	/**
	 * Get the specific service.
	 *
	 * @param id the service id
	 * @return the service object
	 */
	public Service getService(String id) {
		return getService(canonicalId(id));
	}

	/**
	 * Get expire time of this DIDDocument.
	 *
	 * @return the expire time
	 */
	public Date getExpires() {
		return expires;
	}

	/**
	 * Get last modified time of this DIDDocument.
	 *
	 * @return the last modified time
	 */
	public Date getLastModified() {
		return getProof().getCreated();
	}

	/**
	 * Get signature of this DIDDocumet.
	 *
	 * <p>
	 * For single-signed DIDDocument object, the document signature is the
	 * proof's signature. For multi-signed DIDDocument object, the document
	 * signature is the first proof's signature.
	 * </p>
	 *
	 * @return the signature string
	 */
	public String getSignature() {
		return getProof().getSignature();
	}

	/**
	 * Get the proof object of this DIDDocument. if this document is a
	 * multi-signed document, this method returns the first proof object.
	 *
	 * @return the Proof object
	 */
	protected Proof getProof() {
		return _proofs.get(0);
	}

	/**
	 * Get all Proof objects.
	 *
	 * @return an array of the Proof objects
	 */
	public List<Proof> getProofs() {
		return Collections.unmodifiableList(_proofs);
	}

	/**
	 * Return the subject DID.
	 *
	 * @return a DID object
	 */
	@Override
	protected DID getSerializeContextDid() {
		return getSubject();
	}

	/**
	 * Sanitize routine before sealing or after deserialization.
	 *
	 * @throws MalformedDocumentException if the document object is invalid
	 */
	@Override
	protected void sanitize() throws MalformedDocumentException {
		sanitizeControllers();
		sanitizePublickKey();
		sanitizeCredential();
		sanitizeService();

		if (expires == null)
			throw new MalformedDocumentException("Missing document expires.");

		sanitizeProof();
	}

	private void sanitizeControllers() throws MalformedDocumentException {
		if (controllers == null || controllers.isEmpty()) {
			controllers = Collections.emptyList();
			controllerDocs = Collections.emptyMap();

			if (multisig != null)
				throw new MalformedDocumentException("Invalid multisig property");

			return;
		}

		controllerDocs = new HashMap<DID, DIDDocument>();
		try {
			for (DID did : controllers) {
				DIDDocument doc = did.resolve();
				if (doc == null)
					throw new MalformedDocumentException("Can not resolve controller: " + did);

				controllerDocs.put(did, doc);
			}
		} catch (DIDResolveException e) {
				throw new  MalformedDocumentException("Can not resolve the controller's DID");
		}

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

		if (controllers.size() == 1)
			effectiveController = controllers.get(0);
	}

	private void sanitizePublickKey() throws MalformedDocumentException {
		Map<DIDURL, PublicKey> pks = new TreeMap<DIDURL, PublicKey>();

		if (_publickeys != null && _publickeys.size() > 0) {
			for (PublicKey pk : _publickeys) {
				if (pk.getId().getDid() == null) {
					pk.getId().setDid(getSubject());
				} else {
					if (!pk.getId().getDid().equals(getSubject()))
						throw new MalformedDocumentException("Invalid public key id: " + pk.getId());
				}

				if (pks.containsKey(pk.getId()))
					throw new MalformedDocumentException("Public key already exists: " + pk.getId());

				if (pk.getPublicKeyBase58().isEmpty())
					throw new MalformedDocumentException("Invalid public key base58 value.");

				if (pk.getType() == null)
					pk.type = Constants.DEFAULT_PUBLICKEY_TYPE;

				if (pk.getController() == null)
					pk.controller = getSubject();

				pks.put(pk.getId(), pk);
			}
		}

		if (_authentications != null && _authentications.size() > 0) {
			PublicKey pk;

			for (PublicKeyReference keyRef : _authentications) {
				if (keyRef.isVirtual()) {
					if (keyRef.getId().getDid() == null) {
						keyRef.getId().setDid(getSubject());
					} else {
						if (!keyRef.getId().getDid().equals(getSubject()))
							throw new MalformedDocumentException("Invalid publicKey id: " + keyRef.getId());
					}

					pk = pks.get(keyRef.getId());
					if (pk == null)
						throw new MalformedDocumentException("Not exists publicKey reference: " + keyRef.getId());

					keyRef.update(pk);
				} else {
					pk = keyRef.getPublicKey();

					if (keyRef.getId().getDid() == null) {
						keyRef.getId().setDid(getSubject());
					} else {
						if (!keyRef.getId().getDid().equals(getSubject()))
							throw new MalformedDocumentException("Invalid publicKey id: " + keyRef.getId());
					}

					if (pks.containsKey(pk.getId()))
						throw new MalformedDocumentException("Public key already exists: " + pk.getId());

					if (pk.getPublicKeyBase58().isEmpty())
						throw new MalformedDocumentException("Invalid public key base58 value.");

					if (pk.getType() == null)
						pk.type = Constants.DEFAULT_PUBLICKEY_TYPE;

					if (pk.getController() == null)
						pk.controller = getSubject();

					pks.put(pk.getId(), pk);
				}

				pk.setAuthenticationKey(true);
			}

			Collections.sort(_authentications);
		} else {
			_authentications = Collections.emptyList();
		}

		if (_authorizations != null && _authorizations.size() > 0) {
			PublicKey pk;

			for (PublicKeyReference keyRef : _authorizations) {
				if (keyRef.isVirtual()) {
					if (keyRef.getId().getDid() == null) {
						keyRef.getId().setDid(getSubject());
					} else {
						if (!keyRef.getId().getDid().equals(getSubject()))
							throw new MalformedDocumentException("Invalid publicKey id: " + keyRef.getId());
					}

					pk = pks.get(keyRef.getId());
					if (pk == null)
						throw new MalformedDocumentException("Not exists publicKey reference: " + keyRef.getId());

					keyRef.update(pk);
				} else {
					pk = keyRef.getPublicKey();

					if (keyRef.getId().getDid() == null) {
						keyRef.getId().setDid(getSubject());
					} else {
						if (!keyRef.getId().getDid().equals(getSubject()))
							throw new MalformedDocumentException("Invalid publicKey id: " + keyRef.getId());
					}

					if (pks.containsKey(pk.getId()))
						throw new MalformedDocumentException("Public key already exists: " + pk.getId());

					if (pk.getPublicKeyBase58().isEmpty())
						throw new MalformedDocumentException("Invalid public key base58 value.");

					if (pk.getType() == null)
						pk.type = Constants.DEFAULT_PUBLICKEY_TYPE;

					if (pk.getController() == null)
						throw new MalformedDocumentException("Public key missing controller: " + pk.getId());
					else {
						if (pk.getController().equals(getSubject()))
							throw new MalformedDocumentException("Authorization key with wrong controller: " + pk.getId());
					}

					pks.put(pk.getId(), pk);
				}

				pk.setAuthorizationKey(true);
			}

			Collections.sort(_authorizations);
		} else {
			_authorizations = Collections.emptyList();
		}

		// for customized DID with controller, could be no public keys
		if (pks.size() > 0) {
			this.publicKeys = pks;
			this._publickeys = new ArrayList<PublicKey>(pks.values());
		} else {
			this.publicKeys = Collections.emptyMap();
			this._publickeys = Collections.emptyList();
		}

		// Find default key
		for (PublicKey pk : publicKeys.values()) {
			if (pk.getController().equals(getSubject())) {
				String address = HDKey.toAddress(pk.getPublicKeyBytes());
				if (address.equals(getSubject().getMethodSpecificId())) {
					defaultPublicKey = pk;
					if (!pk.isAuthenticationKey()) {
						pk.setAuthenticationKey(true);
						if (_authentications.isEmpty()) {
							_authentications = new ArrayList<PublicKeyReference>();
							_authentications.add(new PublicKeyReference(pk));
						} else {
							_authentications.add(new PublicKeyReference(pk));
							Collections.sort(_authentications);
						}
					}

					break;
				}
			}
		}

		if (controllers.isEmpty() && defaultPublicKey == null)
			throw new MalformedDocumentException("Missing default public key.");
	}

	private void sanitizeCredential() throws MalformedDocumentException {
		if (_credentials == null || _credentials.isEmpty()) {
			_credentials = Collections.emptyList();
			credentials = Collections.emptyMap();
			return;
		}

		Map<DIDURL, VerifiableCredential> vcs = new TreeMap<DIDURL, VerifiableCredential>();
		for (VerifiableCredential vc : _credentials) {
			if (vc.getId() == null)
				throw new MalformedDocumentException("Missing credential id.");

			if (vc.getId().getDid() == null) {
				vc.getId().setDid(getSubject());
			} else {
				if (!vc.getId().getDid().equals(getSubject()))
					throw new MalformedDocumentException("Invalid crdential id: " + vc.getId());
			}

			if (vcs.containsKey(vc.getId()))
				throw new MalformedDocumentException("Credential already exists: " + vc.getId());

			if (vc.getSubject().getId() == null)
				vc.getSubject().setId(getSubject());

			try {
				vc.sanitize();
			} catch (DIDSyntaxException e) {
				throw new MalformedDocumentException("Invalid credential: " + vc.getId(), e);
			}

			vcs.put(vc.getId(), vc);
		}

		this.credentials = vcs;
		this._credentials = new ArrayList<VerifiableCredential>(credentials.values());
	}

	private void sanitizeService() throws MalformedDocumentException {
		if (_services == null || _services.isEmpty()) {
			_services = Collections.emptyList();
			services = Collections.emptyMap();
			return;
		}

		Map<DIDURL, Service> svcs = new TreeMap<DIDURL, Service>();
		for (Service svc : _services) {
			if (svc.getId().getDid() == null) {
				svc.getId().setDid(getSubject());
			} else {
				if (!svc.getId().getDid().equals(getSubject()))
					throw new MalformedDocumentException("Invalid crdential id: " + svc.getId());
			}

			if (svc.getType().isEmpty())
				throw new MalformedDocumentException("Invalid service type.");

			if (svc.getServiceEndpoint() == null || svc.getServiceEndpoint().isEmpty())
				throw new MalformedDocumentException("Missing service endpoint.");

			if (svcs.containsKey(svc.getId()))
				throw new MalformedDocumentException("Service already exists: " + svc.getId());

			svcs.put(svc.getId(), svc);
		}

		this.services = svcs;
		this._services = new ArrayList<Service>(svcs.values());
	}

	private void sanitizeProof() throws MalformedDocumentException {
		if (_proofs == null || _proofs.isEmpty())
			throw new MalformedDocumentException("Missing document proof");

		this.proofs = new HashMap<DID, Proof>();

		for (Proof proof : _proofs) {
			if (proof.getCreator() == null) {
				if (defaultPublicKey != null)
					proof.creator = defaultPublicKey.getId();
				else if (controllers.size() == 1)
					proof.creator = controllerDocs.get(controllers.get(0)).getDefaultPublicKeyId();
				else
					throw new MalformedDocumentException("Missing creator key");
			} else {
				if (proof.getCreator().getDid() == null) {
					if (defaultPublicKey != null)
						proof.getCreator().setDid(getSubject());
					else if (controllers.size() == 1)
						proof.getCreator().setDid(controllers.get(0));
					else
						throw new MalformedDocumentException("Invalid creator key");
				}
			}

			if (proofs.containsKey(proof.getCreator().getDid()))
				throw new MalformedDocumentException("Aleady exist proof from " + proof.getCreator().getDid());

			proofs.put(proof.getCreator().getDid(), proof);
		}

		this._proofs = new ArrayList<Proof>(proofs.values());
		Collections.sort(this._proofs);
	}

	/**
	 * Set the metadata object for this DIDDocument.
	 *
	 * @param metadata a DIDMetadata object
	 */
	protected void setMetadata(DIDMetadata metadata) {
		this.metadata = metadata;
		subject.setMetadata(metadata);
	}

	/**
	 * Get the metadata object of this DIDDocument.
	 *
	 * @return the DIDMetadata object
	 */
	public synchronized DIDMetadata getMetadata() {
		if (metadata == null) {
			/*
			// This will cause resolve recursively
			try {
				DIDDocument resolved = getSubject().resolve();
				metadata = resolved != null ? resolved.getMetadata() : new DIDMetadata(getSubject());
			} catch (DIDResolveException e) {
				metadata = new DIDMetadata(getSubject());
			}
			*/
			metadata = new DIDMetadata(getSubject());
		}

		return metadata;
	}

	protected DIDStore getStore() {
		return getMetadata().getStore();
	}

	/**
	 * Check if this DIDDocument is expired.
	 *
	 * @return true if expired, false otherwise
	 */
	public boolean isExpired() {
		Calendar now = Calendar.getInstance(Constants.UTC);

		Calendar expireDate  = Calendar.getInstance(Constants.UTC);
		expireDate.setTime(expires);

		return now.after(expireDate);
	}

	/**
	 * Check is this DIDDocument is genuine.
	 *
	 * @return true if genuine, false otherwise
	 */
	public boolean isGenuine() {
		// Proofs count should match with multisig
		int expectedProofs = multisig == null ? 1 : multisig.m();
		if (proofs.size() != expectedProofs)
			return false;

		DIDDocument doc = new DIDDocument(this, false);
		String json = doc.serialize(true);
		byte[] digest = EcdsaSigner.sha256Digest(json.getBytes());

		// Document should signed(only) by default public key.
		if (!isCustomizedDid()) {
			Proof proof = getProof();

			// Unsupported public key type;
			if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE))
				return false;

			if (!proof.getCreator().equals(getDefaultPublicKeyId()))
				return false;

			return verifyDigest(proof.getCreator(), proof.getSignature(), digest);
		} else {
			for (Proof proof : _proofs) {
				// Unsupported public key type;
				if (!proof.getType().equals(Constants.DEFAULT_PUBLICKEY_TYPE))
					return false;

				DIDDocument controllerDoc = getControllerDocument(proof.getCreator().getDid());
				if (controllerDoc == null)
					return false;

				if (!controllerDoc.isGenuine())
					return false;

				if (!proof.getCreator().equals(controllerDoc.getDefaultPublicKeyId()))
					return false;

				if (!controllerDoc.verifyDigest(proof.getCreator(), proof.getSignature(), digest))
					return false;
			}

			return true;
		}
	}

	/**
	 * Check if this DIDDocument is deactivated.
	 *
	 * @return true if deactivated, false otherwise
	 */
	public boolean isDeactivated() {
		return getMetadata().isDeactivated();
	}

	/**
	 * Check if this DIDDocument is qualified. It means the proof matched
	 * With the multisig specification.
	 *
	 * @return true if qualified, false otherwise
	 */
	public boolean isQualified() {
		if (_proofs == null || _proofs.isEmpty())
			return false;

		return _proofs.size() == (multisig == null ? 1 : multisig.m());
	}

	/**
	 * Check if this DIDDocument is valid.
	 *
	 * @return true if valid, false otherwise
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

	private DIDDocument copy() {
		DIDDocument doc = new DIDDocument(subject);

		doc.controllers = new ArrayList<DID>(controllers);
		doc.controllerDocs = new HashMap<DID, DIDDocument>(controllerDocs);
		if (this.multisig != null)
			doc.multisig = new MultiSignature(this.multisig);
		doc.publicKeys = new TreeMap<DIDURL, PublicKey>(publicKeys);
		doc.defaultPublicKey = this.defaultPublicKey;
		doc.credentials = new TreeMap<DIDURL, VerifiableCredential>(credentials);
		doc.services = new TreeMap<DIDURL, Service>(services);
		doc.expires = expires;
		doc.proofs = new HashMap<DID, Proof>(proofs);

		DIDMetadata metadata = getMetadata().clone();
		doc.setMetadata(metadata);

		return doc;
	}

	/**
	 * Get DIDDocument Builder object to editing this DIDDocument.
	 *
	 * @return the Builder object
	 */
	public Builder edit() {
		if (!isCustomizedDid()) {
			checkAttachedStore();

			return new Builder(this);
		} else {
			if (getEffectiveController() == null)
				throw new NoEffectiveControllerException();

			return edit(getEffectiveControllerDocument());
		}

	}

	/**
	 * Get DIDDocument Builder object to editing this DIDDocument.
	 *
	 * @param controller the effective controller to editing a customized DIDDocument
	 * @return the Builder object
	 */
	public Builder edit(DIDDocument controller) {
		checkIsCustomized();

		if (!getMetadata().attachedStore() && ! controller.getMetadata().attachedStore())
			throw new NotAttachedWithStoreException();

		if (!controller.getMetadata().attachedStore())
			controller.getMetadata().attachStore(getMetadata().getStore());

		if (!hasController(controller.getSubject()))
			throw new NotControllerException(controller.getSubject().toString());

		return new Builder(this, controller);
	}

	/**
	 * Sign the data by the specified key.
	 *
	 * @param id the key id to sign the data
	 * @param storepass the password for the DIDStore
	 * @param data the data be signed
	 * @return the signature string
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public String sign(DIDURL id, String storepass, byte[] ... data)
			throws DIDStoreException {
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkArgument(data != null && data.length > 0, "Invalid input data");
		checkAttachedStore();

		byte[] digest = EcdsaSigner.sha256Digest(data);
		return signDigest(id, storepass, digest);
	}

	/**
	 * Sign the data by the specified key.
	 *
	 * @param id the key id to sign the data
	 * @param storepass the password for the DIDStore
	 * @param data the data be signed
	 * @return the signature string
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public String sign(String id, String storepass, byte[] ... data)
			throws DIDStoreException {
		return sign(canonicalId(id), storepass, data);
	}

	/**
	 * Sign the data using the default key.
	 *
	 * @param storepass the password for the DIDStore
	 * @param data the data be signed
	 * @return the signature string
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public String sign(String storepass, byte[] ... data) throws DIDStoreException {
		return sign((DIDURL)null, storepass, data);
	}

	/**
	 * Sign the digest by the specified key.
	 *
	 * @param id the key id to sign the data
	 * @param storepass the password for the DIDStore
	 * @param digest the raw digest to be signed
	 * @return the signature string
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public String signDigest(DIDURL id, String storepass, byte[] digest)
			throws DIDStoreException {
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkArgument(digest != null && digest.length > 0, "Invalid digest");
		checkAttachedStore();

		PublicKey pk = id != null ? getPublicKey(id) : getDefaultPublicKey();
		if (pk == null) {
			if (id != null)
				throw new InvalidKeyException(id.toString());
			else
				throw new NoEffectiveControllerException(getSubject().toString());
		}

		return getMetadata().getStore().sign(pk.getId(), storepass, digest);
	}

	/**
	 * Sign the digest by the specified key.
	 *
	 * @param id the key id to sign the data
	 * @param storepass the password for the DIDStore
	 * @param digest the raw digest to be signed
	 * @return the signature string
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public String signDigest(String id, String storepass, byte[] digest)
			throws DIDStoreException {
		return signDigest(canonicalId(id), storepass, digest);
	}

	/**
	 * Sign the digest by the default key.
	 *
	 * @param storepass the password for the DIDStore
	 * @param digest the raw digest to be signed
	 * @return the signature string
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public String signDigest(String storepass, byte[] digest)
			throws DIDStoreException {
		return signDigest((DIDURL)null, storepass, digest);
	}

	/**
	 * Verify the signature by the specific key and the data.
	 *
	 * @param id the key id
	 * @param signature the signature string
	 * @param data the data to be checked
	 * @return true if the signature was verified, false otherwise
	 */
	public boolean verify(DIDURL id, String signature, byte[] ... data) {
		checkArgument(signature != null && !signature.isEmpty(), "Invalid signature");
		checkArgument(data != null && data.length > 0, "Invalid digest");

		byte[] digest = EcdsaSigner.sha256Digest(data);
		return verifyDigest(id, signature, digest);
	}

	/**
	 * Verify the signature by the specific key and the data.
	 *
	 * @param id the key id
	 * @param signature the signature string
	 * @param data the data to be checked
	 * @return true if the signature was verified, false otherwise
	 */
	public boolean verify(String id, String signature, byte[] ... data) {
		return verify(canonicalId(id), signature, data);
	}

	/**
	 * Verify the signature by the default key and the data.
	 *
	 * @param signature the signature string
	 * @param data the data to be checked
	 * @return true if the signature was verified, false otherwise
	 */
	public boolean verify(String signature, byte[] ... data) {
		return verify((DIDURL)null, signature, data);
	}

	/**
	 * Verify the signature by the specific key and the raw digest.
	 *
	 * @param id the key id
	 * @param signature the signature string
	 * @param digest the raw digest to be checked
	 * @return true if the signature was verified, false otherwise
	 */
	public boolean verifyDigest(DIDURL id, String signature, byte[] digest) {
		checkArgument(signature != null && !signature.isEmpty(), "Invalid signature");
		checkArgument(digest != null && digest.length > 0, "Invalid digest");

		PublicKey pk = id != null ? getPublicKey(id) : getDefaultPublicKey();
		if (pk == null) {
			if (id != null)
				throw new InvalidKeyException(id.toString());
			else
				throw new InvalidKeyException("No explicit publicKey");
		}

		byte[] binkey = pk.getPublicKeyBytes();
		byte[] sig = Base64.decode(signature,
				Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);

		return EcdsaSigner.verify(binkey, sig, digest);
	}

	/**
	 * Verify the signature by the specific key and the raw digest.
	 *
	 * @param id the key id
	 * @param signature the signature string
	 * @param digest the raw digest to be checked
	 * @return true if the signature was verified, false otherwise
	 */
	public boolean verifyDigest(String id, String signature, byte[] digest) {
		return verifyDigest(canonicalId(id), signature, digest);
	}

	/**
	 * Verify the signature by the default key and the raw digest.
	 *
	 * @param signature the signature string
	 * @param digest the raw digest to be checked
	 * @return true if the signature was verified, false otherwise
	 */
	public boolean verifyDigest(String signature, byte[] digest) {
		return verifyDigest((DIDURL)null, signature, digest);
	}

	/**
	 * Create a JwtBuilder instance using current DIDDocument.
	 *
	 * <p>
	 * When the JwtBuilder sign the JWT, the JwtBuilder will lookup the keys
	 * through this DIDDocument object.
	 * </p>
	 *
	 * @return a JwtBuilder instance
	 */
	public JwtBuilder jwtBuilder() {
		JwtBuilder builder = new JwtBuilder(getSubject().toString(), new KeyProvider() {

			@Override
			public java.security.PublicKey getPublicKey(String id) {
				return getKeyPair(canonicalId(id)).getPublic();
			}

			@Override
			public PrivateKey getPrivateKey(String id, String storepass)
					throws DIDStoreException {
				return getKeyPair(canonicalId(id), storepass).getPrivate();
			}
		});

		return builder.setIssuer(getSubject().toString());
	}

	/**
	 * Create a JwtParserBuilder instance using current DIDDocument.
	 *
	 * <p>
	 * When the JwtParserBuilder verify the JWT, the JwtParserBuilder will
	 * lookup the keys through this DIDDocument object.
	 * </p>
	 *
	 * @return a JwtParserBuilder instance
	 */
	public JwtParserBuilder jwtParserBuilder() {
		JwtParserBuilder jpb = new JwtParserBuilder(new KeyProvider() {

			@Override
			public java.security.PublicKey getPublicKey(String id) {
				return getKeyPair(canonicalId(id)).getPublic();
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
	 * Create a new customized DID using current DID as the controller.
	 *
	 * @param did the new customized identifier
	 * @param force do not try to resolving the DID, create the document directly
	 * @param storepass the password for the DIDStore
	 * @return the new created DIDDocument
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument newCustomizedDid(DID did, boolean force, String storepass)
			throws DIDResolveException, DIDStoreException {
		return newCustomizedDid(did, null, 1, force, storepass);
	}

	/**
	 * Create a new customized DID using current DID as the controller.
	 *
	 * @param did the new customized identifier
	 * @param storepass the password for the DIDStore
	 * @return the new created DIDDocument
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument newCustomizedDid(DID did, String storepass)
			throws DIDResolveException, DIDStoreException {
		return newCustomizedDid(did, false, storepass);
	}

	/**
	 * Create a new customized DID using current DID as the controller.
	 *
	 * @param did the new customized identifier
	 * @param force do not try to resolving the DID, create the document directly
	 * @param storepass the password for the DIDStore
	 * @return the new created DIDDocument
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument newCustomizedDid(String did, boolean force, String storepass)
			throws DIDResolveException, DIDStoreException {
		return newCustomizedDid(DID.valueOf(did), force, storepass);
	}

	/**
	 * Create a new customized DID using current DID as the controller.
	 *
	 * @param did the new customized identifier
	 * @param storepass the password for the DIDStore
	 * @return the new created DIDDocument
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument newCustomizedDid(String did, String storepass)
			throws DIDResolveException, DIDStoreException {
		return newCustomizedDid(DID.valueOf(did), false, storepass);
	}

	/**
	 * Create a new customized DID using current DID as the controller.
	 *
	 * @param did the new customized identifier
	 * @param controllers the other controllers for the new customized DID
	 * @param multisig how many signatures are required
	 * @param force do not try to resolving the DID, create the document directly
	 * @param storepass the password for the DIDStore
	 * @return the new created DIDDocument
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument newCustomizedDid(DID did, DID[] controllers, int multisig,
			boolean force, String storepass)
			throws DIDResolveException, DIDStoreException {
		checkArgument(did != null, "Invalid DID");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkAttachedStore();

		List<DID> ctrls = new ArrayList<DID>();
		if (controllers != null && controllers.length > 0) {
			for (DID ctrl : controllers) {
				if (ctrl.equals(getSubject()) || ctrls.contains(ctrl))
					continue;

				ctrls.add(ctrl);
			}
		}

		checkArgument(multisig >= 0 && multisig <= ctrls.size() + 1, "Invalid multisig");

		log.info("Creating new DID {} with controller {}...", did, getSubject());

		DIDDocument doc = null;
		if (!force) {
			doc = did.resolve(true);
			if (doc != null)
				throw new DIDAlreadyExistException(did.toString());
		}

		log.info("Creating new DID {} with controller {}...", did, getSubject());

		DIDDocument.Builder db = new DIDDocument.Builder(did, this, getStore());
		for (DID ctrl : ctrls)
			db.addController(ctrl);

		db.setMultiSignature(multisig);

		try {
			doc = db.seal(storepass);
			getStore().storeDid(doc);
			return doc;
		} catch (MalformedDocumentException ignore) {
			throw new UnknownInternalException(ignore);
		}
	}

	/**
	 * Create a new customized DID using current DID as the controller.
	 *
	 * @param did the new customized identifier
	 * @param controllers the other controllers for the new customized DID
	 * @param multisig how many signatures are required
	 * @param storepass the password for the DIDStore
	 * @return the new created DIDDocument
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument newCustomizedDid(DID did, DID[] controllers, int multisig,
			String storepass) throws DIDResolveException, DIDStoreException {
		return newCustomizedDid(did, controllers, multisig, false, storepass);
	}

	/**
	 * Create a new customized DID using current DID as the controller.
	 *
	 * @param did the new customized identifier
	 * @param controllers the other controllers for the new customized DID
	 * @param multisig how many signatures are required
	 * @param force do not try to resolving the DID, create the document directly
	 * @param storepass the password for the DIDStore
	 * @return the new created DIDDocument
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument newCustomizedDid(String did, String controllers[],
			int multisig, boolean force, String storepass)
			throws DIDResolveException, DIDStoreException {
		List<DID> _controllers = new ArrayList<DID>(controllers.length);
		for (String ctrl : controllers)
			_controllers.add(new DID(ctrl));

		return newCustomizedDid(DID.valueOf(did),_controllers.toArray(new DID[0]),
				multisig, force, storepass);
	}

	/**
	 * Create a new customized DID using current DID as the controller.
	 *
	 * @param did the new customized identifier
	 * @param controllers the other controllers for the new customized DID
	 * @param multisig how many signatures are required
	 * @param storepass the password for the DIDStore
	 * @return the new created DIDDocument
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument newCustomizedDid(String did, String controllers[],
			int multisig, String storepass)
			throws DIDResolveException, DIDStoreException {
		return newCustomizedDid(did, controllers, multisig, false, storepass);
	}

	/**
	 * Create a TransferTicket object for the this (customized) DIDDocument.
	 * The document should have an effective controller, otherwise this method
	 * will fail.
	 *
	 * @param to who the did will transfer to
	 * @param storepass the password for the DIDStore
	 * @return the TransferTicket object
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public TransferTicket createTransferTicket(DID to, String storepass)
			throws DIDResolveException, DIDStoreException {
		checkArgument(to != null, "Invalid to");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkIsCustomized();
		checkAttachedStore();
		checkHasEffectiveController();

		TransferTicket ticket = new TransferTicket(this, to);
		ticket.seal(getEffectiveControllerDocument(), storepass);
		return ticket;
	}

	/**
	 * Create a TransferTicket object(as a controller of the customized DID).
	 *
	 * @param did the target customized DID to be transfer
	 * @param to who the did will transfer to
	 * @param storepass the password for the DIDStore
	 * @return the TransferTicket object
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public TransferTicket createTransferTicket(DID did, DID to, String storepass)
			throws DIDResolveException, DIDStoreException {
		checkArgument(did != null, "Invalid did");
		checkArgument(to != null, "Invalid to");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkIsPrimitive();
		checkAttachedStore();

		DIDDocument target = did.resolve(true);
		if (target == null)
			throw new DIDNotFoundException(did.toString());

		if (target.isDeactivated())
			throw new DIDDeactivatedException(did.toString());

		if (!target.isCustomizedDid())
			throw new NotCustomizedDIDException(did.toString());

		if (!target.hasController(getSubject()))
			throw new NotControllerException(getSubject().toString());

		TransferTicket ticket = new TransferTicket(target, to);
		ticket.seal(this, storepass);
		return ticket;
	}

	/**
	 * Sign and seal the TransferTicket object. The current DID should be
	 * the controller of the DID that the TransferTicket to be transfer.
	 *
	 * @param ticket the TransferTicket object to be sign
	 * @param storepass the password for the DIDStore
	 * @return the signed TransferTicket object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public TransferTicket sign(TransferTicket ticket, String storepass)
			throws DIDStoreException {
		checkArgument(ticket != null, "Invalid ticket");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkAttachedStore();

		ticket.seal(this, storepass);
		return ticket;
	}

	/**
	 * Sign and seal the customized DIDDocument object. The current DID should
	 * be the controller of the target DIDDocument.
	 *
	 * @param doc the customized DIDDocument object to be sign
	 * @param storepass the password for the DIDStore
	 * @return the signed DIDDocument object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument sign(DIDDocument doc, String storepass) throws DIDStoreException {
		checkArgument(doc != null, "Invalid document");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkAttachedStore();

		if (!doc.isCustomizedDid())
			throw new NotCustomizedDIDException(doc.getSubject().toString());

		if (!doc.hasController(getSubject()))
			throw new NotControllerException();

		if (isCustomizedDid()) {
			if (getEffectiveController() == null)
				throw new NoEffectiveControllerException(getSubject().toString());
		} else {
			if (!doc.hasController(getSubject()))
				throw new NotControllerException(getSubject().toString());
		}

		if (doc.proofs.containsKey(getSubject()))
			throw new AlreadySignedException(getSubject().toString());

		Builder builder = doc.edit(this);
		try {
			return builder.seal(storepass);
		} catch (MalformedDocumentException ignore) {
			throw new UnknownInternalException(ignore);
		}
	}

	/**
	 * Publish a DID transfer transaction for current (customized) DIDDocument.
	 *
	 * @param ticket the TransferTicket for current DID
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(TransferTicket ticket, DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		checkArgument(ticket.isValid(), "Invalid ticket");
		checkArgument(ticket.getSubject().equals(getSubject()), "Ticket mismatch with current DID");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkIsCustomized();
		checkArgument(proofs.containsKey(ticket.getTo()), "Document not signed by: " + ticket.getTo());
		checkAttachedStore();

		if (signKey == null && getDefaultPublicKeyId() == null)
			throw new NoEffectiveControllerException(getSubject().toString());

		DID did = getSubject();
		DIDDocument targetDoc = did.resolve(true);
		if (targetDoc == null)
			throw new DIDNotFoundException(did.toString());

		if (targetDoc.isDeactivated())
			throw new DIDDeactivatedException(did.toString());

		if (signKey == null) {
			signKey = getDefaultPublicKeyId();
		} else {
			if (getAuthenticationKey(signKey) == null)
				throw new InvalidKeyException(signKey.toString());
		}

		DIDBackend.getInstance().transferDid(this, ticket, signKey, storepass, adapter);
	}

	/**
	 * Publish a DID transfer transaction for current (customized) DIDDocument.
	 *
	 * @param ticket the TransferTicket for current DID
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(TransferTicket ticket, DIDURL signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		publish(ticket,signKey, storepass, null);
	}

	/**
	 * Publish a DID transfer transaction for current (customized) DIDDocument.
	 *
	 * @param ticket the TransferTicket for current DID
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(TransferTicket ticket, String signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		publish(ticket, canonicalId(signKey), storepass, adapter);
	}

	/**
	 * Publish a DID transfer transaction for current (customized) DIDDocument.
	 *
	 * @param ticket the TransferTicket for current DID
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(TransferTicket ticket, String signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		publish(ticket, canonicalId(signKey), storepass, null);
	}

	/**
	 * Publish a DID transfer transaction for current (customized) DIDDocument.
	 * Sign the transaction using the default key.
	 *
	 * @param ticket the TransferTicket for current DID
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(TransferTicket ticket, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		publish(ticket, (DIDURL)null, storepass, adapter);
	}

	/**
	 * Publish a DID transfer transaction for current (customized) DIDDocument.
	 * Sign the transaction using the default key.
	 *
	 * @param ticket the TransferTicket for current DID
	 * @param storepass the password for the DIDStore
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(TransferTicket ticket, String storepass)
			throws DIDStoreException, DIDBackendException {
		publish(ticket, (DIDURL)null, storepass, null);
	}

	/**
	 * Publish a DID transfer transaction for current (customized) DIDDocument
	 * in asynchronous mode.
	 *
	 * @param ticket the TransferTicket for current DID
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(TransferTicket ticket,
			DIDURL signKey, String storepass, DIDTransactionAdapter adapter) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				publish(ticket, signKey, storepass, adapter);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Publish a DID transfer transaction for current (customized) DIDDocument
	 * in asynchronous mode.
	 *
	 * @param ticket the TransferTicket for current DID
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(TransferTicket ticket,
			DIDURL signKey, String storepass) {
		return publishAsync(ticket, signKey, storepass, null);
	}

	/**
	 * Publish a DID transfer transaction for current (customized) DIDDocument
	 * in asynchronous mode.
	 *
	 * @param ticket the TransferTicket for current DID
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(TransferTicket ticket,
			String signKey, String storepass, DIDTransactionAdapter adapter) {
		return publishAsync(ticket, canonicalId(signKey), storepass, adapter);
	}

	/**
	 * Publish a DID transfer transaction for current (customized) DIDDocument
	 * in asynchronous mode.
	 *
	 * @param ticket the TransferTicket for current DID
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(TransferTicket ticket,
			String signKey, String storepass) {
		return publishAsync(ticket, canonicalId(signKey), storepass, null);
	}

	/**
	 * Publish a DID transfer transaction for current (customized) DIDDocument
	 * in asynchronous mode. Sign the transaction using the default key.
	 *
	 * @param ticket the TransferTicket for current DID
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(TransferTicket ticket,
			String storepass, DIDTransactionAdapter adapter) {
		return publishAsync(ticket, (DIDURL)null, storepass, adapter);
	}

	/**
	 * Publish a DID transfer transaction for current (customized) DIDDocument
	 * in asynchronous mode. Sign the transaction using the default key.
	 *
	 * @param ticket the TransferTicket for current DID
	 * @param storepass the password for the DIDStore
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(TransferTicket ticket, String storepass) {
		return publishAsync(ticket, (DIDURL)null, storepass, null);
	}

	/**
	 * Publish DID Document to the ID chain.
	 *
	 * @param signKey the key to sign the transaction
	 * @param force if true will ignore the conflict between local copy and
	 * 				the chain copy; otherwise will check the conflict
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(DIDURL signKey, boolean force, String storepass,
			DIDTransactionAdapter adapter) throws DIDStoreException, DIDBackendException {
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkAttachedStore();

		if (signKey == null && getDefaultPublicKeyId() == null)
			throw new NoEffectiveControllerException(getSubject().toString());

		log.info("Publishing DID {}, force={}...", getSubject(), force);

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

				log.error("Publish failed because DID is deactivated.");
				throw new DIDDeactivatedException(getSubject().toString());
			}

			if (isCustomizedDid()) {
				List<DID> orgControllers = resolvedDoc.getControllers();
				List<DID> curControllers = getControllers();

				if (!curControllers.equals(orgControllers))
					throw new DIDControllersChangedException();
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

		if (signKey == null) {
			signKey = getDefaultPublicKeyId();
		} else {
			if (getAuthenticationKey(signKey) == null)
				throw new InvalidKeyException(signKey.toString());
		}

		if (lastTxid == null || lastTxid.isEmpty()) {
			log.info("Try to publish[create] {}...", getSubject());
			DIDBackend.getInstance().createDid(this, signKey, storepass, adapter);
		} else {
			log.info("Try to publish[update] {}...", getSubject());
			DIDBackend.getInstance().updateDid(this, lastTxid, signKey, storepass, adapter);
		}

		getMetadata().setPreviousSignature(reolvedSignautre);
		getMetadata().setSignature(getProof().getSignature());
	}

	/**
	 * Publish DID Document to the ID chain.
	 *
	 * @param signKey the key to sign the transaction
	 * @param force if true will ignore the conflict between local copy and
	 * 				the chain copy; otherwise will check the conflict
	 * @param storepass the password for the DIDStore
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(DIDURL signKey, boolean force, String storepass)
			throws DIDStoreException, DIDBackendException {
		publish(signKey, force, storepass, null);
	}

	/**
	 * Publish DID Document to the ID chain.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		publish(signKey, false, storepass, adapter);
	}

	/**
	 * Publish DID Document to the ID chain.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(DIDURL signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		publish(signKey, false, storepass, null);
	}

	/**
	 * Publish DID Document to the ID chain.
	 *
	 * @param signKey the key to sign the transaction
	 * @param force if true will ignore the conflict between local copy and
	 * 				the chain copy; otherwise will check the conflict
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(String signKey, boolean force, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		publish(canonicalId(signKey), force, storepass, adapter);
	}

	/**
	 * Publish DID Document to the ID chain.
	 *
	 * @param signKey the key to sign the transaction
	 * @param force if true will ignore the conflict between local copy and
	 * 				the chain copy; otherwise will check the conflict
	 * @param storepass the password for the DIDStore
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(String signKey, boolean force, String storepass)
			throws DIDStoreException, DIDBackendException {
		publish(canonicalId(signKey), force, storepass, null);
	}

	/**
	 * Publish DID Document to the ID chain.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(String signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		publish(canonicalId(signKey), false, storepass, adapter);
	}

	/**
	 * Publish DID Document to the ID chain.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(String signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		publish(canonicalId(signKey), false, storepass, null);
	}

	/**
	 * Publish DID Document to the ID chain. Sign the transaction using
	 * the default key.
	 *
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		publish((DIDURL)null, false, storepass, adapter);
	}

	/**
	 * Publish DID Document to the ID chain. Sign the transaction using
	 * the default key.
	 *
	 * @param storepass the password for the DIDStore
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void publish(String storepass) throws DIDStoreException, DIDBackendException {
		publish((DIDURL)null, false, storepass, null);
	}

	/**
	 * Publish DID Document to the ID chain in asynchronous mode.
	 *
	 * @param signKey the key to sign the transaction
	 * @param force if true will ignore the conflict between local copy and
	 * 				the chain copy; otherwise will check the conflict
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(DIDURL signKey, boolean force,
			String storepass, DIDTransactionAdapter adapter) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				publish(signKey, force, storepass, adapter);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Publish DID Document to the ID chain in asynchronous mode.
	 *
	 * @param signKey the key to sign the transaction
	 * @param force if true will ignore the conflict between local copy and
	 * 				the chain copy; otherwise will check the conflict
	 * @param storepass the password for the DIDStore
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(DIDURL signKey, boolean force,
			String storepass) {
		return publishAsync(signKey, force, storepass, null);
	}

	/**
	 * Publish DID Document to the ID chain in asynchronous mode.
	 *
	 * @param signKey the key to sign the transaction
	 * @param force if true will ignore the conflict between local copy and
	 * 				the chain copy; otherwise will check the conflict
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(String signKey, boolean force,
			String storepass, DIDTransactionAdapter adapter) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				publish(signKey, force, storepass, adapter);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Publish DID Document to the ID chain in asynchronous mode.
	 *
	 * @param signKey the key to sign the transaction
	 * @param force if true will ignore the conflict between local copy and
	 * 				the chain copy; otherwise will check the conflict
	 * @param storepass the password for the DIDStore
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(String signKey, boolean force,
			String storepass) {
		return publishAsync(signKey, force, storepass, null);
	}

	/**
	 * Publish DID Document to the ID chain in asynchronous mode.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(DIDURL signKey, String storepass,
			DIDTransactionAdapter adapter) {
		return publishAsync(signKey, false, storepass, adapter);
	}

	/**
	 * Publish DID Document to the ID chain in asynchronous mode.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(DIDURL signKey, String storepass) {
		return publishAsync(signKey, false, storepass, null);
	}

	/**
	 * Publish DID Document to the ID chain in asynchronous mode.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(String signKey, String storepass,
			DIDTransactionAdapter adapter) {
		return publishAsync(signKey, false, storepass, adapter);
	}

	/**
	 * Publish DID Document to the ID chain in asynchronous mode.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(String signKey, String storepass) {
		return publishAsync(signKey, false, storepass, null);
	}

	/**
	 * Publish DID Document to the ID chain in asynchronous mode. Sign the
	 * transaction using the default key.
	 *
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(String storepass, DIDTransactionAdapter adapter) {
		return publishAsync((DIDURL)null, false, storepass, adapter);
	}

	/**
	 * Publish DID Document to the ID chain in asynchronous mode. Sign the
	 * transaction using the default key.
	 *
	 * @param storepass the password for the DIDStore
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> publishAsync(String storepass) {
		return publishAsync((DIDURL)null, false, storepass, null);
	}

	/**
	 * Deactivate this DID using the authentication key.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void deactivate(DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkAttachedStore();

		if (signKey == null && getDefaultPublicKeyId() == null)
			throw new NoEffectiveControllerException(getSubject().toString());

		signKey = canonicalId(signKey);

		// Document should use the IDChain's copy
		DIDDocument doc = getSubject().resolve(true);
		if (doc == null)
			throw new DIDNotFoundException(getSubject().toString());
		else if (doc.isDeactivated())
			throw new DIDDeactivatedException(getSubject().toString());
		else
			doc.getMetadata().attachStore(getStore());

		if (signKey == null) {
			signKey = doc.getDefaultPublicKeyId();
		} else {
			if (!doc.isCustomizedDid()) {
				// the signKey should be default key or authorization key
				if (!doc.getDefaultPublicKeyId().equals(signKey) &&
						doc.getAuthorizationKey(signKey) == null)
					throw new InvalidKeyException(signKey.toString());
			} else {
				// the signKey should be controller's default key
				DIDDocument controller = doc.getControllerDocument(signKey.getDid());
				if (controller == null || !controller.getDefaultPublicKeyId().equals(signKey))
					throw new InvalidKeyException(signKey.toString());
			}
		}

		DIDBackend.getInstance().deactivateDid(doc, signKey, storepass, adapter);

		if (!getSignature().equals(doc.getSignature()))
			getStore().storeDid(doc);
	}

	/**
	 * Deactivate this DID using the authentication key.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void deactivate(DIDURL signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		deactivate(signKey, storepass, null);
	}

	/**
	 * Deactivate this DID using the authentication key.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void deactivate(String signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		deactivate(canonicalId(signKey), storepass, adapter);
	}

	/**
	 * Deactivate this DID using the authentication key.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void deactivate(String signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		deactivate(canonicalId(signKey), storepass, null);
	}

	/**
	 * Deactivate this DID using the authentication key. Sign the transaction
	 * using the default key.
	 *
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void deactivate(String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		deactivate((DIDURL)null, storepass, adapter);
	}

	/**
	 * Deactivate this DID using the authentication key. Sign the transaction
	 * using the default key.
	 *
	 * @param storepass the password for the DIDStore
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void deactivate(String storepass) throws DIDStoreException, DIDBackendException {
		deactivate((DIDURL)null, storepass, null);
	}

	/**
	 * Deactivate this DID using the authentication key in asynchronous mode.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> deactivateAsync(DIDURL signKey, String storepass,
			DIDTransactionAdapter adapter) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				deactivate(signKey, storepass, adapter);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Deactivate this DID using the authentication key in asynchronous mode.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> deactivateAsync(DIDURL signKey, String storepass) {
		return deactivateAsync(signKey, storepass, null);
	}

	/**
	 * Deactivate this DID using the authentication key in asynchronous mode.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> deactivateAsync(String signKey, String storepass,
			DIDTransactionAdapter adapter) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				deactivate(signKey, storepass, adapter);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Deactivate this DID using the authentication key in asynchronous mode.
	 *
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for the DIDStore
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> deactivateAsync(String signKey, String storepass) {
		return deactivateAsync(signKey, storepass, (DIDTransactionAdapter)null);
	}

	/**
	 * Deactivate this DID using the authentication key in asynchronous mode.
	 * Sign the transaction using the default key.
	 *
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> deactivateAsync(String storepass, DIDTransactionAdapter adapter) {
		return deactivateAsync((DIDURL)null, storepass, adapter);
	}

	/**
	 * Deactivate this DID using the authentication key in asynchronous mode.
	 * Sign the transaction using the default key.
	 *
	 * @param storepass the password for the DIDStore
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> deactivateAsync(String storepass) {
		return deactivateAsync((DIDURL)null, storepass, null);
	}

	/**
	 * Deactivate the target DID with the authorization.
	 *
	 * @param target the DID to be deactivated
	 * @param signKey the key to sign the transaction, should be
	 * 		  authorized by the target DID
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void deactivate(DID target, DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		checkArgument(target != null, "Invalid target DID");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkAttachedStore();

		if (signKey == null && getDefaultPublicKeyId() == null)
			throw new NoEffectiveControllerException(getSubject().toString());

		DIDDocument targetDoc = target.resolve(true);
		if (targetDoc == null)
			throw new DIDNotFoundException(target.toString());
		else if (targetDoc.isDeactivated())
			throw new DIDDeactivatedException(target.toString());

		targetDoc.getMetadata().attachStore(getStore());

		if (!targetDoc.isCustomizedDid()) {
			if (targetDoc.getAuthorizationKeyCount() == 0)
				throw new InvalidKeyException("No authorization key from: " + target);

			List<PublicKey> candidatePks = null;
			if (signKey == null) {
				candidatePks = this.getAuthenticationKeys();
			} else {
				PublicKey pk = getAuthenticationKey(signKey);
				if (pk == null)
					throw new InvalidKeyException(signKey.toString());
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
					this, realSignKey, storepass, adapter);
		} else {
			if (!targetDoc.hasController(getSubject()))
				throw new NotControllerException(getSubject().toString());

			if (signKey == null) {
				signKey = getDefaultPublicKeyId();
			} else {
				if (!signKey.equals(getDefaultPublicKeyId()))
					throw new InvalidKeyException(signKey.toString());
			}

			DIDBackend.getInstance().deactivateDid(targetDoc, signKey, storepass, adapter);

			if (getStore().containsDid(target))
				getStore().storeDid(targetDoc);
		}
	}

	/**
	 * Deactivate the target DID with the authorization.
	 *
	 * @param target the DID to be deactivated
	 * @param signKey the key to sign the transaction, should be
	 * 		  authorized by the target DID
	 * @param storepass the password for the DIDStore
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void deactivate(DID target, DIDURL signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		deactivate(target, signKey, storepass, null);
	}

	/**
	 * Deactivate the target DID with the authorization.
	 *
	 * @param target the DID to be deactivated
	 * @param signKey the key to sign the transaction, should be
	 * 		  authorized by the target DID
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void deactivate(String target, String signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		deactivate(DID.valueOf(target), canonicalId(signKey), storepass, adapter);
	}

	/**
	 * Deactivate the target DID with the authorization.
	 *
	 * @param target the DID to be deactivated
	 * @param signKey the key to sign the transaction, should be
	 * 		  authorized by the target DID
	 * @param storepass the password for the DIDStore
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void deactivate(String target, String signKey, String storepass)
			throws DIDStoreException, DIDBackendException {
		deactivate(DID.valueOf(target), canonicalId(signKey), storepass, null);
	}

	/**
	 * Deactivate the target DID with the authorization. This method will
	 * check the authorized key automatically.
	 *
	 * @param target the DID to be deactivated
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void deactivate(DID target, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDBackendException {
		deactivate(target, null, storepass, adapter);
	}

	/**
	 * Deactivate the target DID with the authorization. This method will
	 * check the authorized key automatically.
	 *
	 * @param target the DID to be deactivated
	 * @param storepass the password for the DIDStore
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws DIDBackendException if an error occurred when publishing the transaction
	 */
	public void deactivate(DID target, String storepass)
			throws DIDStoreException, DIDBackendException {
		deactivate(target, null, storepass, null);
	}

	/**
	 * Deactivate the target DID with the authorization in asynchronous mode.
	 *
	 * @param target the DID to be deactivated
	 * @param signKey the key to sign the transaction, should be
	 * 		  authorized by the target DID
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> deactivateAsync(DID target,
			DIDURL signKey, String storepass, DIDTransactionAdapter adapter) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				deactivate(target, signKey, storepass, adapter);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Deactivate the target DID with the authorization in asynchronous mode.
	 *
	 * @param target the DID to be deactivated
	 * @param signKey the key to sign the transaction, should be
	 * 		  authorized by the target DID
	 * @param storepass the password for the DIDStore
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> deactivateAsync(DID target,
			DIDURL signKey, String storepass) {
		return deactivateAsync(target, signKey, storepass, null);
	}

	/**
	 * Deactivate the target DID with the authorization in asynchronous mode.
	 *
	 * @param target the DID to be deactivated
	 * @param signKey the key to sign the transaction, should be
	 * 		  authorized by the target DID
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> deactivateAsync(String target,
			String signKey, String storepass, DIDTransactionAdapter adapter) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				deactivate(target, signKey, storepass, adapter);
			} catch (DIDException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Deactivate the target DID with the authorization in asynchronous mode.
	 *
	 * @param target the DID to be deactivated
	 * @param signKey the key to sign the transaction, should be
	 * 		  authorized by the target DID
	 * @param storepass the password for the DIDStore
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> deactivateAsync(String target,
			String signKey, String storepass) {
		return deactivateAsync(target, signKey, storepass, null);
	}

	/**
	 * Deactivate the target DID with the authorization in asynchronous mode.
	 * This method will check the authorized key automatically.
	 *
	 * @param target the DID to be deactivated
	 * @param storepass the password for the DIDStore
	 * @param adapter an optional DIDTransactionAdapter, if null the method will
	 * 		  use the default adapter from the DIDBackend
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> deactivateAsync(DID target, String storepass,
			DIDTransactionAdapter adapter) {
		return deactivateAsync(target, null, storepass, adapter);
	}

	/**
	 * Deactivate the target DID with the authorization in asynchronous mode.
	 * This method will check the authorized key automatically.
	 *
	 * @param target the DID to be deactivated
	 * @param storepass the password for the DIDStore
	 * @return the new CompletableStage
	 */
	public CompletableFuture<Void> deactivateAsync(DID target, String storepass) {
		return deactivateAsync(target, null, storepass, null);
	}

	/**
	 * Parse the DIDDocument object from a string JSON representation.
	 *
	 * @param content the string JSON content to deserialize the document object
	 * @return the DIDDocument object
	 * @throws MalformedDocumentException if a parse error occurs
	 */
	public static DIDDocument parse(String content) throws MalformedDocumentException {
		try {
			return parse(content, DIDDocument.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedDocumentException)
				throw (MalformedDocumentException)e;
			else
				throw new MalformedDocumentException(e);
		}
	}

	/**
	 * Parse the DIDDocument object from a Reader object.
	 *
	 * @param src the Reader object to deserialize the document object
	 * @return the DIDDocument object
	 * @throws MalformedDocumentException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static DIDDocument parse(Reader src)
			throws MalformedDocumentException, IOException {
		try {
			return parse(src, DIDDocument.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedDocumentException)
				throw (MalformedDocumentException)e;
			else
				throw new MalformedDocumentException(e);
		}
	}

	/**
	 * Parse the DIDDocument object from an InputStream object.
	 *
	 * @param src the input stream object to deserialize the document object
	 * @return the DIDDocument object
	 * @throws MalformedDocumentException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static DIDDocument parse(InputStream src)
			throws MalformedDocumentException, IOException {
		try {
			return parse(src, DIDDocument.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedDocumentException)
				throw (MalformedDocumentException)e;
			else
				throw new MalformedDocumentException(e);
		}
	}

	/**
	 * Parse the DIDDocument object from a File object.
	 *
	 * @param src the File object to deserialize the document object
	 * @return the DIDDocument object
	 * @throws MalformedDocumentException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static DIDDocument parse(File src)
			throws MalformedDocumentException, IOException {
		try {
			return parse(src, DIDDocument.class);
		} catch (DIDSyntaxException e) {
			if (e instanceof MalformedDocumentException)
				throw (MalformedDocumentException)e;
			else
				throw new MalformedDocumentException(e);
		}
	}

	/**
	 * Parse the DIDDocument object from a string JSON representation.
	 *
	 * @param content the string JSON content to deserialize the document object
	 * @return the DIDDocument object
	 * @throws MalformedDocumentException if a parse error occurs
	 * @deprecated use {@link #parse(String)} instead
	 */
	@Deprecated
	public static DIDDocument fromJson(String content) throws MalformedDocumentException {
		return parse(content);
	}

	/**
	 * Parse the DIDDocument object from a Reader object.
	 *
	 * @param src the Reader object to deserialize the document object
	 * @return the DIDDocument object
	 * @throws MalformedDocumentException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(Reader)} instead
	 */
	@Deprecated
	public static DIDDocument fromJson(Reader src)
			throws MalformedDocumentException, IOException {
		return parse(src);
	}

	/**
	 * Parse the DIDDocument object from an InputStream object.
	 *
	 * @param src the input stream object to deserialize the document object
	 * @return the DIDDocument object
	 * @throws MalformedDocumentException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(InputStream)} instead
	 */
	@Deprecated
	public static DIDDocument fromJson(InputStream src)
			throws MalformedDocumentException, IOException {
		return parse(src);
	}

	/**
	 * Parse the DIDDocument object from a File object.
	 *
	 * @param src the File object to deserialize the document object
	 * @return the DIDDocument object
	 * @throws MalformedDocumentException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #parse(File)} instead
	 */
	@Deprecated
	public static DIDDocument fromJson(File src)
			throws MalformedDocumentException, IOException {
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
			DIDMetadata metadata = new DIDMetadata(did, store);
			this.document.setMetadata(metadata);
		}

		/**
		 * Constructs DID Document Builder with given customizedDid and DIDStore.
		 *
		 * @param did the specified DID
		 * @param controller the effective controller to create the document
		 * @param store the DIDStore object
		 */
		protected Builder(DID did, DIDDocument controller, DIDStore store) {
			this.document = new DIDDocument(did);

			this.document.controllers = new ArrayList<DID>();
			this.document.controllerDocs = new HashMap<DID, DIDDocument>();

			this.document.controllers.add(controller.getSubject());
			this.document.controllerDocs.put(controller.getSubject(), controller);
			this.document.effectiveController = controller.getSubject();

			this.document.setMetadata(new DIDMetadata(did, store));

			this.controllerDoc = controller;
		}

		/**
		 * Constructs DID Document Builder with given DID Document.
		 *
		 * @param doc a DIDDocument object to be modify
		 */
		protected Builder(DIDDocument doc) {
			this.document = doc.copy();
		}

		/**
		 * Construct a builder instance for the customized DID document
		 * with effective controller.
		 *
		 * @param doc a customized DIDDocument object to be modify
		 * @param controller one the the controller of the doc
		 */
		protected Builder(DIDDocument doc, DIDDocument controller) {
			this.document = doc.copy();
			this.document.effectiveController = controller.getSubject();
			// if (controller.getMetadata().attachedStore())
			//	this.document.getMetadata().setStore(controller.getMetadata().getStore());
			this.controllerDoc = controller;
		}

		private DIDURL canonicalId(String id) {
			return DIDURL.valueOf(getSubject(), id);
		}

		private DIDURL canonicalId(DIDURL id) {
			if (id == null || id.getDid() != null)
				return id;

			return new DIDURL(getSubject(), id);
		}

		private void invalidateProof() {
			if (document.proofs != null && !document.proofs.isEmpty())
				document.proofs.clear();
		}

		private void checkNotSealed() throws AlreadySealedException {
			if (document == null)
				throw new AlreadySealedException();
		}

		private void checkIsCustomized() throws NotCustomizedDIDException {
			if (!document.isCustomizedDid())
				throw new NotCustomizedDIDException(document.getSubject().toString());
		}

		/**
		 * Get the subject DID of this builder.
		 *
		 * @return the subject of document builder
		 */
		public DID getSubject() {
			checkNotSealed();
			return document.getSubject();
		}

		/**
		 * Add a new controller to the customized DID document.
		 *
		 * @param controller the new controller's DID
		 * @return the Builder instance for method chaining
		 * @throws DIDResolveException if failed resolve the new controller's DID
		 */
		public Builder addController(DID controller) throws DIDResolveException {
			checkArgument(controller != null, "Invalid controller");
			checkNotSealed();
			checkIsCustomized();
			checkArgument(!document.controllers.contains(controller), "Controller already exists");

			DIDDocument controllerDoc = controller.resolve(true);
			if (controllerDoc == null)
				throw new DIDNotFoundException(controller.toString());

			if (controllerDoc.isDeactivated())
				throw new DIDDeactivatedException(controller.toString());

			if (controllerDoc.isExpired())
				throw new DIDExpiredException(controller.toString());

			if (!controllerDoc.isGenuine())
				throw new DIDNotGenuineException(controller.toString());

			if (controllerDoc.isCustomizedDid())
				throw new NotPrimitiveDIDException(controller.toString());

			document.controllers.add(controller);
			document.controllerDocs.put(controller, controllerDoc);

			document.multisig = null; // invalidate multisig
			invalidateProof();
			return this;
		}

		/**
		 * Add a new controller to the customized DID document.
		 *
		 * @param controller the new controller's DID
		 * @return the Builder instance for method chaining
		 * @throws DIDResolveException if failed resolve the new controller's DID
		 */
		public Builder addController(String controller) throws DIDResolveException {
			return addController(DID.valueOf(controller));
		}

		/**
		 * Remove the specific controller from the customized document.
		 *
		 * @param controller the controller's DID to be remove
		 * @return the Builder instance for method chaining
		 */
		public Builder removeController(DID controller) {
			checkArgument(controller != null, "Invalid controller");
			checkNotSealed();
			checkIsCustomized();
			// checkArgument(document.controllers.contains(controller), "Controller not exists");

			if (controller.equals(controllerDoc.getSubject()))
				throw new CanNotRemoveEffectiveControllerException(controller.toString());

			if (document.controllers.remove(controller)) {
				document.controllerDocs.remove(controller);
				invalidateProof();
			}

			return this;
		}

		/**
		 * Remove the specific controller from the customized document.
		 *
		 * @param controller the controller's DID to be remove
		 * @return the Builder instance for method chaining
		 */
		public Builder removeController(String controller) {
			return removeController(DID.valueOf(controller));
		}

		/**
		 * Set multisig specification for multi-controllers DID document.
		 *
		 * @param m the required signature count
		 * @return the Builder instance for method chaining
		 */
		public Builder setMultiSignature(int m) {
			checkNotSealed();
			checkIsCustomized();
			checkArgument(m >= 1, "Invalid signature count");

			int n = document.controllers.size();
			checkArgument(m <= n, "Signature count exceeds the upper limit");

			MultiSignature multisig = null;
			if (n > 1)
				multisig = new MultiSignature(m, n);

			if (document.multisig == null && multisig == null)
				return this;

			if (document.multisig != null && multisig != null &&
					document.multisig.equals(multisig))
				return this;

			document.multisig = new MultiSignature(m, n);

			invalidateProof();
			return this;
		}

		private void addPublicKey(PublicKey key) {
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
			if (document.defaultPublicKey == null) {
				String address = HDKey.toAddress(key.getPublicKeyBytes());
				if (address.equals(getSubject().getMethodSpecificId())) {
					document.defaultPublicKey = key;
					key.setAuthenticationKey(true);
				}
			}

			invalidateProof();
		}

		/**
		 * Add PublicKey to did document builder.
		 *
		 * @param id the key id
		 * @param type the key type
		 * @param controller the owner of public key
		 * @param pk the base58 encoded public key
		 * @return the Builder instance for method chaining
		 */
		public Builder addPublicKey(DIDURL id, String type, DID controller, String pk) {
			checkNotSealed();
			checkArgument(id != null && (id.getDid() == null || id.getDid().equals(getSubject())),
					"Invalid publicKey id");
			checkArgument(pk != null && !pk.isEmpty(), "Invalid publicKey");

			if (controller == null)
				controller = getSubject();

			addPublicKey(new PublicKey(canonicalId(id), type, controller, pk));
			return this;
		}

		/**
		 * Add PublicKey to did document builder.
		 *
		 * @param id the key id
		 * @param type the key type
		 * @param controller the owner of public key
		 * @param pk the base58 encoded public key
		 * @return the Builder instance for method chaining
		 */
		public Builder addPublicKey(String id, String type, String controller, String pk) {
			return addPublicKey(canonicalId(id), type, DID.valueOf(controller), pk);
		}

		/**
		 * Add PublicKey to did document builder.
		 *
		 * @param id the key id
		 * @param controller the owner of public key
		 * @param pk the base58 encoded public key
		 * @return the Builder instance for method chaining
		 */
		public Builder addPublicKey(DIDURL id, DID controller, String pk) {
			return addPublicKey(id, null, controller, pk);
		}

		/**
		 * Add PublicKey to did document builder.
		 *
		 * @param id the key id
		 * @param controller the owner of public key
		 * @param pk the base58 encoded public key
		 * @return the Builder instance for method chaining
		 */
		public Builder addPublicKey(String id, String controller, String pk) {
			return addPublicKey(id, null, controller, pk);
		}

		/**
		 * Add PublicKey to did document builder.
		 *
		 * @param id the key id
		 * @param pk the base58 encoded public key
		 * @return the Builder instance for method chaining
		 */
		public Builder addPublicKey(DIDURL id, String pk) {
			return addPublicKey(id, null, null, pk);
		}

		/**
		 * Add PublicKey to did document builder.
		 *
		 * @param id the key id
		 * @param pk the base58 encoded public key
		 * @return the Builder instance for method chaining
		 */
		public Builder addPublicKey(String id, String pk) {
			return addPublicKey(id, null, null, pk);
		}

		/**
		 * Remove the specific public key from the document.
		 * If call this method with forced mode, it will remove the key
		 * even it reference by the others.
		 *
		 * @param id the key id to be remove
		 * @param force if true will remove the key even it reference by the others
		 * @return the Builder instance for method chaining
		 */
		public Builder removePublicKey(DIDURL id, boolean force) {
			checkNotSealed();
			checkArgument(id != null, "Invalid publicKey id");

			if (document.publicKeys == null || document.publicKeys.isEmpty())
				throw new DIDObjectNotExistException(id.toString());

			id = canonicalId(id);
			PublicKey pk = document.publicKeys.get(id);
			if (pk == null)
				throw new DIDObjectNotExistException(id.toString());

			// Can not remove default public key
			if (document.defaultPublicKey != null && document.defaultPublicKey.getId().equals(id))
				throw new DIDObjectHasReferenceException(id.toString() + "is default key");

			if (!force) {
				if (pk.isAuthenticationKey() || pk.isAuthorizationKey())
					throw new DIDObjectHasReferenceException(id.toString());
			}

			if (document.publicKeys.remove(id) != null) {
				try {
					// TODO: should delete the loosed private key when store the document
					if (document.getMetadata().attachedStore())
						document.getMetadata().getStore().deletePrivateKey(id);
				} catch (DIDStoreException ignore) {
					log.error("INTERNAL - Remove private key", ignore);
				}

				invalidateProof();
			}

			return this;
		}

		/**
		 * Remove the specific public key from the document.
		 * If call this method with forced mode, it will remove the key
		 * even it reference by the others.
		 *
		 * @param id the key id to be remove
		 * @param force if true will remove the key even it reference by the others
		 * @return the Builder instance for method chaining
		 */
		public Builder removePublicKey(String id, boolean force) {
			return removePublicKey(canonicalId(id), force);
		}

		/**
		 * Remove the specific public key from the document.
		 * It should not reference by authentication or authorization when
		 * removing the public key.
		 *
		 * @param id the key id to be remove
		 * @return the Builder instance for method chaining
		 */
		public Builder removePublicKey(DIDURL id) {
			return removePublicKey(id, false);
		}

		/**
		 * Remove the specific public key from the document.
		 * It should not reference by authentication or authorization when
		 * removing the public key.
		 *
		 * @param id the key id to be remove
		 * @return the Builder instance for method chaining
		 */
		public Builder removePublicKey(String id) {
			return removePublicKey(id, false);
		}

		/**
		 * Add an exists public key as authentication key.
		 *
		 * @param id the key id to be add to authentication keys
		 * @return the Builder instance for method chaining
		 */
		public Builder addAuthenticationKey(DIDURL id) {
			checkNotSealed();
			checkArgument(id != null, "Invalid publicKey id");

			if (document.publicKeys == null || document.publicKeys.isEmpty())
				throw new DIDObjectNotExistException(id.toString());

			id = canonicalId(id);
			PublicKey key = document.publicKeys.get(id);
			if (key == null)
				throw new DIDObjectNotExistException(id.toString());

			// Check the controller is current DID subject
			if (!key.getController().equals(getSubject()))
				throw new IllegalUsageException(id.toString());

			if (!key.isAuthenticationKey()) {
				key.setAuthenticationKey(true);
				invalidateProof();
			}

			return this;
		}

		/**
		 * Add an exists public key as authentication key.
		 *
		 * @param id the key id to be add to authentication keys
		 * @return the Builder instance for method chaining
		 */
		public Builder addAuthenticationKey(String id) {
			return addAuthenticationKey(canonicalId(id));
		}

		/**
		 * Add a new authentication key to the document.
		 *
		 * @param id the new authentication key id
		 * @param pk the base58 encoded public key
		 * @return the Builder instance for method chaining
		 */
		public Builder addAuthenticationKey(DIDURL id, String pk) {
			checkNotSealed();
			checkArgument(id != null && (id.getDid() == null || id.getDid().equals(getSubject())),
					"Invalid publicKey id");
			checkArgument(pk != null && !pk.isEmpty(), "Invalid publicKey");

			PublicKey key = new PublicKey(canonicalId(id), null, getSubject(), pk);
			key.setAuthenticationKey(true);
			addPublicKey(key);

			return this;
		}

		/**
		 * Add a new authentication key to the document.
		 *
		 * @param id the new authentication key id
		 * @param pk the base58 encoded public key
		 * @return the Builder instance for method chaining
		 */
		public Builder addAuthenticationKey(String id, String pk) {
			return addAuthenticationKey(canonicalId(id), pk);
		}

		/**
		 * Remove the specific authentication key from the document.
		 * After remove the authentication key, the key still in the
		 * public keys, this method only remove the authentication
		 * reference from the public key.
		 *
		 * @param id the key id to be remove
		 * @return the Builder instance for method chaining
		 */
		public Builder removeAuthenticationKey(DIDURL id) {
			checkNotSealed();
			checkArgument(id != null, "Invalid publicKey id");

			if (document.publicKeys == null || document.publicKeys.isEmpty())
				throw new DIDObjectNotExistException(id.toString());

			id = canonicalId(id);
			PublicKey key = document.publicKeys.get(id);
			if (key == null || !key.isAuthenticationKey())
				throw new DIDObjectNotExistException(id.toString());

			// Can not remove default public key
			if (document.defaultPublicKey != null && document.defaultPublicKey.getId().equals(id))
				throw new DIDObjectHasReferenceException(
						"Cannot remove the default PublicKey from authentication.");

			if (key.isAuthenticationKey()) {
				key.setAuthenticationKey(false);
				invalidateProof();
			} else {
				throw new DIDObjectNotExistException(id.toString());
			}

			return this;
		}

		/**
		 * Remove the specific authentication key from the document.
		 * After remove the authentication key, the key still in the
		 * public keys, this method only remove the authentication
		 * reference from the public key.
		 *
		 * @param id the key id to be remove
		 * @return the Builder instance for method chaining
		 */
		public Builder removeAuthenticationKey(String id) {
			return removeAuthenticationKey(canonicalId(id));
		}

		/**
		 * Add an exists public key as authorization key.
		 *
		 * @param id the key id to be add to authorization keys
		 * @return the Builder instance for method chaining
		 */
		public Builder addAuthorizationKey(DIDURL id) {
			checkNotSealed();
			checkArgument(id != null, "Invalid publicKey id");

			if (document.isCustomizedDid())
				throw new NotPrimitiveDIDException(getSubject().toString());

			if (document.publicKeys == null || document.publicKeys.isEmpty())
				throw new DIDObjectNotExistException(id.toString());

			id = canonicalId(id);
			PublicKey key = document.publicKeys.get(id);
			if (key == null)
				throw new DIDObjectNotExistException(id.toString());

			// Can not authorize to self
			if (key.getController().equals(getSubject()))
				throw new IllegalUsageException(id.toString());

			if (!key.isAuthorizationKey()) {
				key.setAuthorizationKey(true);
				invalidateProof();
			}

			return this;
		}

		/**
		 * Add an exists public key as authorization key.
		 *
		 * @param id the key id to be add to authorization keys
		 * @return the Builder instance for method chaining
		 */
		public Builder addAuthorizationKey(String id) {
			return addAuthorizationKey(canonicalId(id));
		}

		/**
		 * Add a new authorization key.
		 *
		 * @param id the new authorization key id
		 * @param controller the owner of the authorization
		 * @param pk the base58 encoded public key
		 * @return the Builder instance for method chaining
		 */
		public Builder addAuthorizationKey(DIDURL id, DID controller, String pk) {
			checkNotSealed();
			checkArgument(id != null && (id.getDid() == null || id.getDid().equals(getSubject())),
					"Invalid publicKey id");
			checkArgument(pk != null && !pk.isEmpty(), "Invalid publicKey");

			if (document.isCustomizedDid())
				throw new NotPrimitiveDIDException(getSubject().toString());

			// Can not authorize to self
			if (controller.equals(getSubject()))
				throw new IllegalUsageException("Key's controller is self.");

			PublicKey key = new PublicKey(canonicalId(id), null, controller, pk);
			key.setAuthorizationKey(true);
			addPublicKey(key);

			return this;
		}

		/**
		 * Add a new authorization key.
		 *
		 * @param id the new authorization key id
		 * @param controller the owner of the authorization
		 * @param pk the base58 encoded public key
		 * @return the Builder instance for method chaining
		 */
		public Builder addAuthorizationKey(String id, String controller, String pk) {
			return addAuthorizationKey(canonicalId(id), DID.valueOf(controller), pk);
		}

		/**
		 * Authorize to the DID and the specific key.
		 *
		 * @param id the new authorization key id
		 * @param controller the DID that authorized to
		 * @param key the key id that controller by the controller to be authorize
		 * @return the Builder instance for method chaining
		 * @throws DIDResolveException if an error occurred when resolving the DIDs
		 */
		public Builder authorizeDid(DIDURL id, DID controller, DIDURL key)
				throws DIDResolveException {
			checkNotSealed();
			checkArgument(id != null && (id.getDid() == null || id.getDid().equals(getSubject())),
					"Invalid publicKey id");
			checkArgument(controller != null && !controller.equals(getSubject()), "Invalid controller");

			if (document.isCustomizedDid())
				throw new NotPrimitiveDIDException(getSubject().toString());

			DIDDocument controllerDoc = controller.resolve();
			if (controllerDoc == null)
				throw new DIDNotFoundException(id.toString());

			if (controllerDoc.isDeactivated())
				throw new DIDDeactivatedException(controller.toString());

			if (controllerDoc.isExpired())
				throw new DIDExpiredException(controller.toString());

			if (!controllerDoc.isGenuine())
				throw new DIDNotGenuineException(controller.toString());

			if (controllerDoc.isCustomizedDid())
				throw new NotPrimitiveDIDException(controller.toString());

			if (key == null)
				key = controllerDoc.getDefaultPublicKeyId();

				// Check the key should be a authentication key.
			PublicKey targetPk = controllerDoc.getAuthenticationKey(key);
			if (targetPk == null)
				throw new DIDObjectNotExistException(key.toString());

			PublicKey pk = new PublicKey(canonicalId(id), targetPk.getType(),
					controller, targetPk.getPublicKeyBase58());
			pk.setAuthorizationKey(true);
			addPublicKey(pk);

			return this;
		}

		/**
		 * Authorize to the DID and the DID's default key.
		 *
		 * @param id the new authorization key id
		 * @param controller the DID that authorized to
		 * @return the Builder instance for method chaining
		 * @throws DIDResolveException if an error occurred when resolving the DIDs
		 */
		public Builder authorizeDid(DIDURL id, DID controller)
				throws DIDResolveException {
			return authorizeDid(id, controller, null);
		}

		/**
		 * Authorize to the DID and the specific key.
		 *
		 * @param id the new authorization key id
		 * @param controller the DID that authorized to
		 * @param key the key id that controller by the controller to be authorize
		 * @return the Builder instance for method chaining
		 * @throws DIDResolveException if an error occurred when resolving the DIDs
		 */
		public Builder authorizeDid(String id, String controller, String key)
				throws DIDResolveException {
			return authorizeDid(canonicalId(id),
					DID.valueOf(controller), DIDURL.valueOf(controller, key));
		}

		/**
		 * Authorize to the DID and the DID's default key.
		 *
		 * @param id the new authorization key id
		 * @param controller the DID that authorized to
		 * @return the Builder instance for method chaining
		 * @throws DIDResolveException if an error occurred when resolving the DIDs
		 */
		public Builder authorizeDid(String id, String controller)
				throws DIDResolveException {
			return authorizeDid(id, controller, null);
		}

		/**
		 * Remove the specific authorization key from the document.
		 * After remove the authorization key, the key still in the
		 * public keys, this method only remove the authorization
		 * reference from the public key.
		 *
		 * @param id the key id to be remove
		 * @return the Builder instance for method chaining
		 */
		public Builder removeAuthorizationKey(DIDURL id) {
			checkNotSealed();
			checkArgument(id != null, "Invalid publicKey id");

			if (document.publicKeys == null || document.publicKeys.isEmpty())
				throw new DIDObjectNotExistException(id.toString());

			id = canonicalId(id);
			PublicKey key = document.publicKeys.get(id);
			if (key == null)
				throw new DIDObjectNotExistException(id.toString());

			if (key.isAuthorizationKey()) {
				key.setAuthorizationKey(false);
				invalidateProof();
			} else {
				throw new DIDObjectNotExistException(id.toString());
			}

			return this;
		}

		/**
		 * Remove the specific authorization key from the document.
		 * After remove the authorization key, the key still in the
		 * public keys, this method only remove the authorization
		 * reference from the public key.
		 *
		 * @param id the key id to be remove
		 * @return the Builder instance for method chaining
		 */
		public Builder removeAuthorizationKey(String id) {
			return removeAuthorizationKey(canonicalId(id));
		}

		/**
		 * Add a credential object to the document.
		 *
		 * @param vc the VerifiableCredential object to be add
		 * @return the Builder instance for method chaining
		 */
		public Builder addCredential(VerifiableCredential vc) {
			checkNotSealed();
			checkArgument(vc != null, "Invalid credential");

			// Check the credential belongs to current DID.
			if (!vc.getSubject().getId().equals(getSubject()))
				throw new IllegalUsageException(vc.getSubject().getId().toString());

			if (document.credentials == null) {
				document.credentials = new TreeMap<DIDURL, VerifiableCredential>();
			} else {
				if (document.credentials.containsKey(vc.getId()))
					throw new DIDObjectAlreadyExistException(vc.getId().toString());
			}

			document.credentials.put(vc.getId(), vc);
			invalidateProof();

			return this;
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param types the credential types
		 * @param subject the claims for the credential subject
		 * @param expirationDate the expiration time for the credential
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(DIDURL id, String[] types,
				Map<String, Object> subject, Date expirationDate, String storepass)
				throws DIDStoreException {
			checkNotSealed();
			checkArgument(id != null && (id.getDid() == null || id.getDid().equals(getSubject())),
					"Invalid publicKey id");
			checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

			Issuer issuer = new Issuer(document);
			VerifiableCredential.Builder cb = issuer.issueFor(document.getSubject());
			if (types == null)
				types = new String[]{ "SelfProclaimedCredential" };

			if (expirationDate == null)
				expirationDate = document.getExpires();

			try {
				VerifiableCredential vc = cb.id(canonicalId(id))
						.type(types)
						.properties(subject)
						.expirationDate(expirationDate)
						.seal(storepass);

				addCredential(vc);
			} catch (MalformedCredentialException ignore) {
				throw new UnknownInternalException(ignore);
			}

			return this;
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param types the credential types
		 * @param subject the claims for the credential subject
		 * @param expirationDate the expiration time for the credential
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(String id, String[] types,
				Map<String, Object> subject, Date expirationDate, String storepass)
				throws DIDStoreException {
			return addCredential(canonicalId(id), types, subject,
					expirationDate, storepass);
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param subject the claims for the credential subject
		 * @param expirationDate the expiration time for the credential
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(DIDURL id, Map<String, Object> subject,
				Date expirationDate, String storepass) throws DIDStoreException {
			return addCredential(id, null, subject, expirationDate, storepass);
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param subject the claims for the credential subject
		 * @param expirationDate the expiration time for the credential
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(String id, Map<String, Object> subject,
				Date expirationDate, String storepass) throws DIDStoreException {
			return addCredential(canonicalId(id), null, subject, expirationDate, storepass);
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param types the credential types
		 * @param subject the claims for the credential subject
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(DIDURL id, String[] types,
				Map<String, Object> subject, String storepass) throws DIDStoreException {
			return addCredential(id, types, subject, null, storepass);
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param types the credential types
		 * @param subject the claims for the credential subject
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(String id, String[] types,
				Map<String, Object> subject, String storepass) throws DIDStoreException {
			return addCredential(canonicalId(id), types, subject, null, storepass);
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param subject the claims for the credential subject
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(DIDURL id, Map<String, Object> subject,
				String storepass) throws DIDStoreException {
			return addCredential(id, null, subject, null, storepass);
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param subject the claims for the credential subject
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(String id, Map<String, Object> subject,
				String storepass) throws DIDStoreException {
			return addCredential(canonicalId(id), null, subject, null, storepass);
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param types the credential types
		 * @param jsonSubject a JSON string represented claims for the credential subject
		 * @param expirationDate the expiration time for the credential
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(DIDURL id, String[] types,
				String jsonSubject, Date expirationDate, String storepass)
				throws DIDStoreException {
			checkNotSealed();
			checkArgument(id != null && (id.getDid() == null || id.getDid().equals(getSubject())),
					"Invalid publicKey id");
			checkArgument(jsonSubject != null && !jsonSubject.isEmpty(), "Invalid json");
			checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

			Issuer issuer = new Issuer(document);
			VerifiableCredential.Builder cb = issuer.issueFor(document.getSubject());
			if (types == null)
				types = new String[]{ "SelfProclaimedCredential" };

			if (expirationDate == null)
				expirationDate = document.expires;

			try {
				VerifiableCredential vc = cb.id(canonicalId(id))
						.type(types)
						.properties(jsonSubject)
						.expirationDate(expirationDate)
						.seal(storepass);

				addCredential(vc);
			} catch (MalformedCredentialException ignore) {
				throw new UnknownInternalException(ignore);
			}

			return this;
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param types the credential types
		 * @param jsonSubject a JSON string represented claims for the credential subject
		 * @param expirationDate the expiration time for the credential
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(String id, String[] types,
				String jsonSubject, Date expirationDate, String storepass)
				throws DIDStoreException {
			return addCredential(canonicalId(id), types, jsonSubject, expirationDate, storepass);
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param jsonSubject a JSON string represented claims for the credential subject
		 * @param expirationDate the expiration time for the credential
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(DIDURL id, String jsonSubject,
				Date expirationDate, String storepass) throws DIDStoreException {
			return addCredential(id, null, jsonSubject, expirationDate, storepass);
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param jsonSubject a JSON string represented claims for the credential subject
		 * @param expirationDate the expiration time for the credential
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(String id, String jsonSubject,
				Date expirationDate, String storepass) throws DIDStoreException {
			return addCredential(canonicalId(id), null, jsonSubject, expirationDate, storepass);
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param types the credential types
		 * @param jsonSubject a JSON string represented claims for the credential subject
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(DIDURL id, String[] types,
				String jsonSubject, String storepass) throws DIDStoreException {
			return addCredential(id, types, jsonSubject, null, storepass);
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param types the credential types
		 * @param jsonSubject a JSON string represented claims for the credential subject
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(String id, String[] types,
				String jsonSubject, String storepass) throws DIDStoreException {
			return addCredential(canonicalId(id), types, jsonSubject, null, storepass);
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param jsonSubject a JSON string represented claims for the credential subject
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(DIDURL id, String jsonSubject, String storepass)
				throws DIDStoreException {
			return addCredential(id, null, jsonSubject, null, storepass);
		}

		/**
		 * Add a self-proclaimed credential to the document.
		 *
		 * @param id the credential id
		 * @param jsonSubject a JSON string represented claims for the credential subject
		 * @param storepass the password for the store
		 * @return the Builder instance for method chaining
		 * @throws DIDStoreException if an error occurred when accessing the store
		 */
		public Builder addCredential(String id, String jsonSubject, String storepass)
				throws DIDStoreException {
			return addCredential(canonicalId(id), null, jsonSubject, null, storepass);
		}

		/**
		 * Remove the specific credential from the document.
		 *
		 * @param id the id of the credential to be remove
		 * @return the Builder instance for method chaining
		 */
		public Builder removeCredential(DIDURL id) {
			checkNotSealed();
			checkArgument(id != null, "Invalid credential id");

			if (document.credentials == null || document.credentials.isEmpty())
				throw new DIDObjectNotExistException(id.toString());

			if (document.credentials.remove(canonicalId(id)) != null)
				invalidateProof();
			else
				throw new DIDObjectNotExistException(id.toString());

			return this;
		}

		/**
		 * Remove the specific credential from the document.
		 *
		 * @param id the id of the credential to be remove
		 * @return the Builder instance for method chaining
		 */
		public Builder removeCredential(String id) {
			return removeCredential(canonicalId(id));
		}

		/**
		 * Add a new service to the document.
		 *
		 * @param id the service id
		 * @param type the service type
		 * @param endpoint the service endpoint
		 * @param properties the application defined extra properties
		 * @return the Builder instance for method chaining
		 */
		public Builder addService(DIDURL id, String type, String endpoint,
				Map<String, Object> properties) {
			checkNotSealed();
			checkArgument(id != null && (id.getDid() == null || id.getDid().equals(getSubject())),
					"Invalid publicKey id");
			checkArgument(type != null && !type.isEmpty(), "Invalid type");
			checkArgument(endpoint != null && !endpoint.isEmpty(), "Invalid endpoint");

			Service svc = new Service(canonicalId(id), type, endpoint, properties);
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
		 * Add a new service to the document.
		 *
		 * @param id the service id
		 * @param type the service type
		 * @param endpoint the service endpoint
		 * @param properties the application defined extra properties
		 * @return the Builder instance for method chaining
		 */
		public Builder addService(String id, String type, String endpoint,
				Map<String, Object> properties) {
			return addService(canonicalId(id), type, endpoint, properties);
		}

		/**
		 * Add a new service to the document.
		 *
		 * @param id the service id
		 * @param type the service type
		 * @param endpoint the service endpoint
		 * @return the Builder instance for method chaining
		 */
		public Builder addService(DIDURL id, String type, String endpoint) {
			return addService(id, type, endpoint, null);
		}

		/**
		 * Add a new service to the document.
		 *
		 * @param id the service id
		 * @param type the service type
		 * @param endpoint the service endpoint
		 * @return the Builder instance for method chaining
		 */
		public Builder addService(String id, String type, String endpoint) {
			return addService(canonicalId(id), type, endpoint, null);
		}

		/**
		 * Remove the specific service from the document.
		 *
		 * @param id the id of the service to be remove
		 * @return the Builder instance for method chaining
		 */
		public Builder removeService(DIDURL id) {
			checkNotSealed();
			checkArgument(id != null, "Invalid credential id");

			if (document.services == null || document.services.isEmpty())
				throw new DIDObjectNotExistException(id.toString());

			if (document.services.remove(canonicalId(id)) != null)
				invalidateProof();
			else
				throw new DIDObjectNotExistException(id.toString());

			return this;
		}

		/**
		 * Remove the specific service from the document.
		 *
		 * @param id the id of the service to be remove
		 * @return the Builder instance for method chaining
		 */
		public Builder removeService(String id) {
			return removeService(canonicalId(id));
		}

		private Calendar getMaxExpires() {
			Calendar cal = Calendar.getInstance(Constants.UTC);
			cal.add(Calendar.YEAR, Constants.MAX_VALID_YEARS);
			return cal;
		}

		/**
		 * Set the document use the default expire time.
		 *
		 * @return the Builder instance for method chaining
		 */
		public Builder setDefaultExpires() {
			checkNotSealed();

			document.expires = getMaxExpires().getTime();
			invalidateProof();

			return this;
		}

		/**
		 * Set the expires time for the document.
		 *
		 * @param expires the expire time
		 * @return the Builder instance for method chaining
		 */
		public Builder setExpires(Date expires) {
			checkNotSealed();
			checkArgument(expires != null, "Invalid expires");

			Calendar cal = Calendar.getInstance(Constants.UTC);
			cal.setTime(expires);

			if (cal.after(getMaxExpires()))
				throw new IllegalArgumentException("Invalid expires, out of range.");

			document.expires = expires;
			invalidateProof();

			return this;
		}

		/**
		 * Remove the proof that created by the specific controller.
		 *
		 * @param controller the controller's DID
		 * @return the Builder instance for method chaining
		 */
		public Builder removeProof(DID controller) {
			checkNotSealed();
			checkArgument(controller != null, "Invalid controller");

			if (document.proofs == null || document.proofs.isEmpty())
				return this;

			if (document.proofs.remove(controller) == null)
				throw new DIDObjectNotExistException("No proof signed by: " + controller);

			return this;
		}

		private void sanitize() throws MalformedDocumentException {
			if (document.isCustomizedDid()) {
				if (document.controllers == null || document.controllers.isEmpty())
					throw new MalformedDocumentException("Missing controllers");

				if (document.controllers.size() > 1) {
					if (document.multisig == null)
						throw new MalformedDocumentException("Missing multisig");

					if (document.multisig.n() != document.controllers.size())
						throw new MalformedDocumentException("Invalid multisig, not matched with controllers");
				} else {
					if (document.multisig != null)
						throw new MalformedDocumentException("Invalid multisig");
				}
			}

			int sigs = document.multisig == null ? 1 : document.multisig.m();
			if (document.proofs != null && document.proofs.size() == sigs)
				throw new AlreadySealedException(getSubject().toString());

			if (document.controllers == null || document.controllers.isEmpty()) {
				document.controllers = Collections.emptyList();
				document.controllerDocs = Collections.emptyMap();
			} else {
				Collections.sort(document.controllers);
			}

			if (document.publicKeys == null || document.publicKeys.isEmpty()) {
				document.publicKeys = Collections.emptyMap();
				document._publickeys = Collections.emptyList();
				document._authentications = Collections.emptyList();
				document._authorizations = Collections.emptyList();
			} else {
				document._publickeys = new ArrayList<PublicKey>(document.publicKeys.values());

				document._authentications = new ArrayList<PublicKeyReference>();
				document._authorizations = new ArrayList<PublicKeyReference>();

				for (PublicKey pk : document.publicKeys.values()) {
					if (pk.isAuthenticationKey())
						document._authentications.add(new PublicKeyReference(pk));

					if (pk.isAuthorizationKey())
						document._authorizations.add(new PublicKeyReference(pk));
				}

				if (document._authentications.isEmpty())
					document._authentications = Collections.emptyList();

				if (document._authentications.isEmpty())
					document._authorizations = Collections.emptyList();
			}

			if (document.credentials == null || document.credentials.isEmpty()) {
				document.credentials = Collections.emptyMap();
				document._credentials = Collections.emptyList();
			} else {
				document._credentials = new ArrayList<VerifiableCredential>(document.credentials.values());
			}

			if (document.services == null || document.services.isEmpty()) {
				document.services = Collections.emptyMap();
				document._services = Collections.emptyList();
			} else {
				document._services = new ArrayList<Service>(document.services.values());
			}

			if (document.proofs == null || document.proofs.isEmpty()) {
				if (document.getExpires() == null)
					setDefaultExpires();
			}

			if (document.proofs == null)
				document.proofs = new HashMap<DID, Proof>();

			document._proofs = null;
		}

		/**
		 * Seal the document object, attach the generated proof to the
		 * document.
		 *
		 * @param storepass the password for the DIDStore
		 * @return the new DIDDocument object
		 * @throws InvalidKeyException if no valid sign key to seal the document
		 * @throws MalformedDocumentException if the DIDDocument is malformed
		 * @throws DIDStoreException if an error occurs when accessing the store
		 */
		public DIDDocument seal(String storepass)
				throws MalformedDocumentException, DIDStoreException {
			checkNotSealed();
			checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

			sanitize();

			DIDDocument	signerDoc = document.isCustomizedDid() ? controllerDoc : document;
			DIDURL signKey = signerDoc.getDefaultPublicKeyId();

			if (document.proofs.containsKey(signerDoc.getSubject()))
				throw new AlreadySignedException(signerDoc.getSubject().toString());

			String json = document.serialize(true);
			String sig = document.sign(signKey, storepass, json.getBytes());
			Proof proof = new Proof(signKey, sig);
			document.proofs.put(proof.getCreator().getDid(), proof);
			document._proofs = new ArrayList<Proof>(document.proofs.values());
			Collections.sort(document._proofs);

			// Invalidate builder
			DIDDocument doc = document;
			this.document = null;

			return doc;
		}
	}
}
