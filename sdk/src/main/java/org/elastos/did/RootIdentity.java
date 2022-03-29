package org.elastos.did;

import static com.google.common.base.Preconditions.checkArgument;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicInteger;

import org.elastos.did.DIDStore.ConflictHandle;
import org.elastos.did.crypto.Base58;
import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.DIDAlreadyExistException;
import org.elastos.did.exception.DIDDeactivatedException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.MalformedDocumentException;
import org.elastos.did.exception.MnemonicException;
import org.elastos.did.exception.RootIdentityAlreadyExistException;
import org.elastos.did.exception.UnknownInternalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.digests.MD5Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.util.encoders.Hex;

/**
 * The RootIdentity is a top-level object that represents a real user who
 * owns a series of DIDs
 *
 * <p>
 * The users could use RootIdentity object to derive a series of DIDs,
 * all these DIDs are managed by this root identity object.
 * At the same time, these DIDs are independent to the 3rd party verifiers.
 * </p>
 */
public final class RootIdentity {
	private String mnemonic;
	private HDKey rootPrivateKey;
	private HDKey preDerivedPublicKey;
	private AtomicInteger index;

	private String id;
	private Metadata metadata;

	private static final Logger log = LoggerFactory.getLogger(RootIdentity.class);

	static class Metadata extends AbstractMetadata {
		public static final String DEFAULT_DID = "defaultDid";

		private String id;

		/**
		 * Construct a Metadata object with given values.
		 *
		 * @param id the id of the RootIdentity object
		 * @param store the target DIDStore
		 */
		protected Metadata(String id, DIDStore store) {
			super(store);
			this.id = id;
		}
		/**
		 * Construct a Metadata object with given values.
		 *
		 * @param id the id of the RootIdentity object
		 */
		protected Metadata(String id) {
			this(id, null);
		}

		/**
		 * The default constructor for JSON deserializer.
		 */
		protected Metadata() {
			this(null);
		}

		/**
		 * Set the RootIdentity's id that this metadata related to.
		 * @param id
		 */
		protected void setId(String id) {
			this.id = id;
		}

		/**
		 * Set the default DID of this RootIdentity.
		 *
		 * @param did a DID object that derived by this RootIdentity object
		 */
		protected void setDefaultDid(DID did) {
			put(DEFAULT_DID, did.toString());
		}

		/**
		 * Get the default DID of this RootIdentity.
		 *
		 * @return a DID that represent as the default DID
		 */
		public DID getDefaultDid() {
			return DID.valueOf(get(DEFAULT_DID));
		}

		/**
		 * Save the modified metadata to the attached store if this metadata
		 * attached with a store.
		 */
		@Override
		protected void save() {
			if (attachedStore()) {
				try {
					getStore().storeRootIdentityMetadata(id, this);
				} catch (DIDStoreException ignore) {
					log.error("INTERNAL - error store metadata for credential {}", id);
				}
			}
		}
	}

	private RootIdentity(String mnemonic, String passphrase) {
		this.mnemonic = mnemonic;

		if (passphrase == null)
			passphrase = "";

		this.rootPrivateKey = new HDKey(mnemonic, passphrase);
		this.preDerivedPublicKey = rootPrivateKey.derive(HDKey.PRE_DERIVED_PUBLICKEY_PATH);
		this.index = new AtomicInteger(0);
	}

	private RootIdentity(HDKey rootPrivateKey) {
		this.rootPrivateKey = rootPrivateKey;
		this.preDerivedPublicKey = rootPrivateKey.derive(HDKey.PRE_DERIVED_PUBLICKEY_PATH);
		this.index = new AtomicInteger(0);
	}

	private RootIdentity(HDKey preDerivedPublicKey, int index) {
		this.preDerivedPublicKey = preDerivedPublicKey;
		this.index = new AtomicInteger(index);
	}

	/**
	 * Create a RootIdentity from mnemonic and an optional passphrase.
	 *
	 * @param mnemonic the mnemonic string
	 * @param passphrase the extra passphrase to generate seed with the mnemonic
	 * @param overwrite true will overwrite the identity if the identity exists
	 * 					in the store, false will raise exception if the identity
	 * 					exists in the store
	 * @param store the DIDStore where to save this identity
	 * @param storepass the password for DIDStore
	 * @return the RootIdentity object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public static RootIdentity create(String mnemonic, String passphrase,
			boolean overwrite, DIDStore store, String storepass) throws DIDStoreException {
		checkArgument(mnemonic != null && !mnemonic.isEmpty(), "Invalid mnemonic");
		checkArgument(store != null, "Invalid DID store");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		try {
			checkArgument(Mnemonic.checkIsValid(mnemonic), "Invalid mnemonic.");
		} catch (MnemonicException e) {
			throw new IllegalArgumentException(e);
		}

		if (passphrase == null)
			passphrase = "";

		RootIdentity identity = new RootIdentity(mnemonic, passphrase);

		if (store.containsRootIdentity(identity.getId()) && !overwrite)
			throw new RootIdentityAlreadyExistException(identity.getId());

		identity.setMetadata(new Metadata(identity.getId(), store));
		store.storeRootIdentity(identity, storepass);
		identity.wipe();

		return identity;
	}

	/**
	 * Create a RootIdentity from mnemonic and an optional passphrase.
	 *
	 * @param mnemonic the mnemonic string
	 * @param passphrase the extra passphrase to generate seed with the mnemonic
	 * @param store the DIDStore where to save this identity
	 * @param storepass the password for DIDStore
	 * @return the RootIdentity object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public static RootIdentity create(String mnemonic, String passphrase,
			DIDStore store, String storepass) throws DIDStoreException {
		return create(mnemonic, passphrase, false, store, storepass);
	}

	/**
	 * Create a RootIdentity from a root extended private key.
	 *
	 * @param extentedPrivateKey the root extended private key
	 * @param overwrite true will overwrite the identity if the identity exists
	 * 					in the store, false will raise exception if the identity
	 * 					exists in the store
	 * @param store the DIDStore where to save this identity
	 * @param storepass the password for DIDStore
	 * @return the RootIdentity object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public static RootIdentity create(String extentedPrivateKey, boolean overwrite,
			DIDStore store, String storepass) throws DIDStoreException {
		checkArgument(extentedPrivateKey != null && !extentedPrivateKey.isEmpty(),
				"Invalid extended private key");
		checkArgument(store != null, "Invalid DID store");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		HDKey rootPrivateKey = HDKey.deserialize(Base58.decode(extentedPrivateKey));
		RootIdentity identity = new RootIdentity(rootPrivateKey);

		if (store.containsRootIdentity(identity.getId()) && !overwrite)
			throw new RootIdentityAlreadyExistException(identity.getId());

		identity.setMetadata(new Metadata(identity.getId(), store));
		store.storeRootIdentity(identity, storepass);
		identity.wipe();

		return identity;
	}

	/**
	 * Create a RootIdentity from a root extended private key.
	 *
	 * @param extentedPrivateKey the root extended private key
	 * @param store the DIDStore where to save this identity
	 * @param storepass the password for DIDStore
	 * @return the RootIdentity object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public static RootIdentity create(String extentedPrivateKey,
			DIDStore store, String storepass) throws DIDStoreException {
		return create(extentedPrivateKey, false, store, storepass);
	}

	/**
	 * Create a public key only RootIdentity instance.
	 *
	 * @param preDerivedPublicKey the pre-derived extended public key
	 * @param index current available derive index
	 * @return the RootIdentity object
	 */
	protected static RootIdentity create(String preDerivedPublicKey, int index) {
		HDKey key = preDerivedPublicKey == null ? null : HDKey.deserializeBase58(preDerivedPublicKey);

		return new RootIdentity(key, index);
	}

	/**
	 * Get RootIdentity Id from mnemonic and an optional passphrase.
	 *
	 * @param mnemonic the mnemonic string
	 * @param passphrase the extra passphrase to generate seed with the mnemonic
	 * @return the RootIdentity Id
	 */
	public static String getId(String mnemonic, String passphrase) {
		checkArgument(mnemonic != null && !mnemonic.isEmpty(), "Invalid mnemonic");

		try {
			checkArgument(Mnemonic.checkIsValid(mnemonic), "Invalid mnemonic.");
		} catch (MnemonicException e) {
			throw new IllegalArgumentException(e);
		}

		if (passphrase == null)
			passphrase = "";

		RootIdentity identity = new RootIdentity(mnemonic, passphrase);
        String id = identity.getId();
		identity.wipe();

		return id;
	}

	/**
	 * Get a RootIdentity Id from a root extended private key.
	 *
	 * @param extentedPrivateKey the root extended private key
	 * @return the RootIdentity Id
	 */
	public static String getId(String extentedPrivateKey) {
		checkArgument(extentedPrivateKey != null && !extentedPrivateKey.isEmpty(),
				"Invalid extended private key");

		HDKey rootPrivateKey = HDKey.deserialize(Base58.decode(extentedPrivateKey));

		RootIdentity identity = new RootIdentity(rootPrivateKey);
		String id = identity.getId();
		identity.wipe();

		return id;
	}

	private void wipe() {
		rootPrivateKey.wipe();

		mnemonic = null;
		rootPrivateKey = null;
	}

	/**
	 * Get the attached DIDStore instance.
	 *
	 * @return a DIDStore object
	 */
	protected DIDStore getStore() {
		return metadata.getStore();
	}

	/**
	 * Get the metadata object of this RootIdentity.
	 *
	 * @param metadata the metadata object
	 */
	protected void setMetadata(Metadata metadata) {
		this.metadata = metadata;
	}

	/**
	 * Calculate the id of RootIdentity object from the pre-derived public key.
	 *
	 * @param key the pre-derived public key in bytes array
	 * @return the id of RootIdentity object
	 */
	protected static String getId(byte[] key) {
		checkArgument(key != null && key.length > 0, "Invalid key bytes");

		MD5Digest md5 = new MD5Digest();
		byte[] digest = new byte[md5.getDigestSize()];
		md5.update(key, 0, key.length);
		md5.doFinal(digest, 0);

		return Hex.toHexString(digest);
	}

	/**
	 * Get the id of this RootIdentity object.
	 *
	 * @return the id of this RootIdentity object
	 */
	public synchronized String getId() {
		if (id == null)
			id = getId(preDerivedPublicKey.serializePublicKey());

		return id;
	}

	/**
	 * Get the alias of this RootIdentity object.
	 *
	 * @return the alias of this RootIdentity object, or null if not set before
	 */
	public String getAlias() {
		return metadata.getAlias();
	}

	/**
	 * Set the alias for this RootIdentity object.
	 *
	 * @param alias the new alias
	 */
	public void setAlias(String alias) {
		metadata.setAlias(alias);
	}

	/**
	 * Set this RootIdentity as the global default identity in current DIDStore.
	 *
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public void setAsDefault() throws DIDStoreException {
		getStore().setDefaultRootIdentity(this);
	}

	/**
	 * Get the default DID of this RootIdentity object.
	 *
	 * @return a DID object or null if not set the default DID before
	 */
	public DID getDefaultDid() {
		DID did = metadata.getDefaultDid();
		if (did == null)
			did = getDid(0);

		return did;
	}

	/**
	 * Set the default DID for this RootIdentity object.
	 *
	 * <p>
	 * The default DID object should derived from this RootIdentity.
	 * </p>
	 *
	 * @param did a DID object
	 */
	public void setDefaultDid(DID did) {
		metadata.setDefaultDid(did);
	}

	/**
	 * Set the default DID for this RootIdentity object.
	 *
	 * <p>
	 * The default DID object should derived from this RootIdentity.
	 * </p>
	 *
	 * @param did a DID string
	 */
	public void setDefaultDid(String did) {
		metadata.setDefaultDid(DID.valueOf(did));
	}

	/**
	 * Set the default DID for this RootIdentity object.
	 *
	 * @param index the index of default DID derived from
	 */
	public void setDefaultDid(int index) {
		checkArgument(index >=0, "Invalid index");

		metadata.setDefaultDid(getDid(index));
	}

	String getMnemonic() {
		return mnemonic;
	}

	HDKey getRootPrivateKey() {
		return rootPrivateKey;
	}

	/**
	 * Get the pre-derived public key of this RootIdentity.
	 *
	 * @return a HDKey object represent the public key
	 */
	protected HDKey getPreDerivedPublicKey() {
		return preDerivedPublicKey;
	}

	/**
	 * Get the next available derive index of this RootIdentity.
	 *
	 * @return the next available derive index
	 */
	protected int getIndex() {
		return index.get();
	}

	/**
	 * Set the next available derive index for this RootIdentity.
	 *
	 * @param idx the next available derive index
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected void setIndex(int idx) throws DIDStoreException {
		index.set(idx);
		getStore().storeRootIdentity(this);
	}

	/**
	 * Increase the next available derive index for this RootIdentity.
	 *
	 * @return the next available derive index
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected int incrementIndex() throws DIDStoreException {
		int idx = index.incrementAndGet();
		getStore().storeRootIdentity(this);
		return idx;
	}

	/**
	 * Get DID that derived from the specific index.
	 *
	 * @param index the derive index
	 * @return a DID object
	 */
	public DID getDid(int index) {
		checkArgument(index >= 0, "Invalid index");

		HDKey key = preDerivedPublicKey.derive("0/" + index);
		DID did = new DID(DID.METHOD, key.getAddress());

		/*
		DIDMetadata metadata = new DIDMetadata(did, getStore());
		metadata.setRootIdentityId(getId());
		metadata.setIndex(index);
		did.setMetadata(metadata);
		*/

		return did;
	}

	static byte[] lazyCreateDidPrivateKey(DIDURL id, DIDStore store, String storepass)
			throws DIDStoreException {
		DIDDocument doc = store.loadDid(id.getDid());
		if (doc == null) {
			log.error("INTERNAL - Missing document for DID: {}", id.getDid());
			throw new DIDStoreException("Missing document for DID: " + id.getDid());
		}

		String identity = doc.getMetadata().getRootIdentityId();
		if (identity == null)
			return null;

		HDKey key = store.derive(identity, HDKey.DERIVE_PATH_PREFIX +
				doc.getMetadata().getIndex(), storepass);

		DIDDocument.PublicKey pk = doc.getPublicKey(id);
		if (pk == null) {
			log.error("INTERNAL - Invalid public key: {}", id);
			throw new DIDStoreException("Invalid public key: " + id);
		}

		if (!key.getPublicKeyBase58().equals(pk.getPublicKeyBase58())) {
			log.error("INTERNAL - Invalid DID metadata: {}", id.getDid());
			throw new DIDStoreException("Invalid DID metadata: " + id.getDid());
		}

		store.storePrivateKey(id, key.serialize(), storepass);
		byte[] sk = key.serialize();
		key.wipe();
		return sk;
	}

	/**
	 * Create a new DID that derive from the specified index.
	 *
	 * @param index the derive index
	 * @param overwrite true for overwriting the existing one, fail otherwise
	 * @param storepass the password for DIDStore
	 * @return the new created DIDDocument object
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument newDid(int index, boolean overwrite, String storepass)
			throws DIDResolveException, DIDStoreException {
		checkArgument(index >= 0, "Invalid index");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		DID did = getDid(index);
		DIDDocument doc = getStore().loadDid(did);
		if (doc != null) {
			if (doc.isDeactivated())
				throw new DIDDeactivatedException(did.toString());

			if (!overwrite)
				throw new DIDAlreadyExistException("DID already exists in the store.");
		}

		try {
			doc = did.resolve();
			if (doc != null) {
				if (doc.isDeactivated())
					throw new DIDDeactivatedException(did.toString());

				if (!overwrite)
					throw new DIDAlreadyExistException("DID already published.");
			}
		} catch (DIDResolveException e) {
			if (!overwrite)
				throw e;
		}


		log.debug("Creating new DID {} at index {}...", did.toString(), index);

		HDKey key = getStore().derive(getId(), HDKey.DERIVE_PATH_PREFIX + index, storepass);
		try {
			DIDURL id = new DIDURL(did, "#primary");
			getStore().storePrivateKey(id, key.serialize(), storepass);

			DIDDocument.Builder db = new DIDDocument.Builder(did, getStore());
			db.addAuthenticationKey(id, key.getPublicKeyBase58());
			doc = db.seal(storepass);

			doc.getMetadata().setRootIdentityId(getId());
			doc.getMetadata().setIndex(index);
			doc.getMetadata().attachStore(getStore());

			getStore().storeDid(doc);

			return doc;
		} catch (MalformedDocumentException ignore) {
			throw new UnknownInternalException(ignore);
		} finally {
			key.wipe();
		}
	}

	/**
	 * Create a new DID that derive from the specified index.
	 *
	 * @param index the derive index
	 * @param storepass the password for DIDStore
	 * @return the new created DIDDocument object
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument newDid(int index, String storepass)
			throws DIDResolveException, DIDStoreException {
		return newDid(index, false, storepass);
	}

	/**
	 * Create a new DID from next available index.
	 *
	 * @param overwrite true for overwriting the existing one, fail otherwise
	 * @param storepass the password for DIDStore
	 * @return the new created DIDDocument object
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public synchronized DIDDocument newDid(boolean overwrite, String storepass)
			throws DIDResolveException, DIDStoreException {
		DIDDocument doc = newDid(getIndex(), overwrite, storepass);
		incrementIndex();
		return doc;
	}

	/**
	 * Create a new DID from next available index.
	 *
	 * @param storepass the password for DIDStore
	 * @return the new created DIDDocument object
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument newDid(String storepass)
			throws DIDResolveException, DIDStoreException {
		return newDid(false, storepass);
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
			path.append(idx & 0x7FFFFFFF).append('/');
		}

		path.append(securityCode & 0x7FFFFFFF);

		return path.toString();
	}

	/**
	 * Get DID that derived from the specific specified application identifier
	 * and the security code.
	 *
	 * @param identifier the application identifier, could be app' package or bundle name
	 * @param securityCode the user defined security code
	 * @return a DID object
	 */
	public DID getDid(String identifier, int securityCode) {
		checkArgument(identifier != null && !identifier.isEmpty(), "Invalid identifier");

		HDKey key = preDerivedPublicKey.derive(mapToDerivePath(identifier, securityCode));
		DID did = new DID(DID.METHOD, key.getAddress());

		/*
		DIDMetadata metadata = new DIDMetadata(did, getStore());
		metadata.setRootIdentityId(getId());
		metadata.setIndex(index);
		did.setMetadata(metadata);
		*/

		return did;
	}

	/**
	 * Create a new DID that derive from the specified application identifier
	 * and the security code.
	 *
	 * @param identifier the application identifier, could be app' package or bundle name
	 * @param securityCode the user defined security code
	 * @param overwrite true for overwriting the existing one, fail otherwise
	 * @param storepass the password for DIDStore
	 * @return the new created DIDDocument object
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument newDid(String identifier, int securityCode, boolean overwrite, String storepass)
			throws DIDResolveException, DIDStoreException {
		checkArgument(identifier != null && !identifier.isEmpty(), "Invalid identifier");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		String path = HDKey.PRE_DERIVED_PUBLICKEY_PATH + "/" + mapToDerivePath(identifier, securityCode);
		HDKey key = getStore().derive(getId(), path, storepass);
		DID did = new DID(DID.METHOD, key.getAddress());

		DIDDocument doc = getStore().loadDid(did);
		if (doc != null) {
			if (doc.isDeactivated())
				throw new DIDDeactivatedException(did.toString());

			if (!overwrite)
				throw new DIDAlreadyExistException("DID already exists in the store.");
		}

		try {
			doc = did.resolve();
			if (doc != null) {
				if (doc.isDeactivated())
					throw new DIDDeactivatedException(did.toString());

				if (!overwrite)
					throw new DIDAlreadyExistException("DID already published.");
			}
		} catch (DIDResolveException e) {
			if (!overwrite)
				throw e;
		}


		log.debug("Creating new DID {} for {}/{}...", did.toString(), identifier, securityCode);

		try {
			DIDURL id = new DIDURL(did, "#primary");
			getStore().storePrivateKey(id, key.serialize(), storepass);

			DIDDocument.Builder db = new DIDDocument.Builder(did, getStore());
			db.addAuthenticationKey(id, key.getPublicKeyBase58());
			doc = db.seal(storepass);

			doc.getMetadata().setRootIdentityId(getId());
			doc.getMetadata().setExtra("application", identifier);
			doc.getMetadata().setExtra("securityCode", securityCode);
			doc.getMetadata().attachStore(getStore());

			getStore().storeDid(doc);

			return doc;
		} catch (MalformedDocumentException ignore) {
			throw new UnknownInternalException(ignore);
		} finally {
			key.wipe();
		}
	}

	/**
	 * Create a new DID that derive from the specified application identifier
	 * and the security code.
	 *
	 * @param identifier the application identifier, could be app' package or bundle name
	 * @param securityCode the user defined security code
	 * @param storepass the password for DIDStore
	 * @return the new created DIDDocument object
	 * @throws DIDResolveException if an error occurred when resolving the DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument newDid(String identifier, int securityCode, String storepass)
			throws DIDResolveException, DIDStoreException {
		return newDid(identifier, securityCode, false, storepass);
	}
	/**
	 * Check whether this RootIdentity created from mnemonic.
	 *
	 * @return true if this RootIdentity created from mnemonic, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean hasMnemonic() throws DIDStoreException {
		return getStore().containsRootIdentityMnemonic(getId());
	}

	/**
	 * Export mnemonic that generated this RootIdentity object.
	 *
	 * @param storepass the password for DIDStore
	 * @return the mnemonic string
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public String exportMnemonic(String storepass) throws DIDStoreException {
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		return getStore().exportRootIdentityMnemonic(getId(), storepass);
	}

	/**
	 * Synchronize the specific DID from ID chain.
	 *
	 * <p>
	 * If the ConflictHandle is not set by the developers, this method will
	 * use the default ConflictHandle implementation: if conflict between
	 * the chain copy and the local copy, it will keep the local copy, but
	 * update the local metadata with the chain copy.
	 * </p>
	 *
	 * @param index the DID derive index
	 * @param handle an application defined handle to process the conflict
	 * 				 between the chain copy and the local copy
	 * @return true if synchronized success, false if not synchronized
	 * @throws DIDResolveException if an error occurred when resolving DID
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean synchronize(int index, ConflictHandle handle)
			throws DIDResolveException, DIDStoreException {
		checkArgument(index >= 0, "Invalid index");

		if (handle == null)
			handle = DIDStore.defaultConflictHandle;

		DID did = getDid(index);
		return getStore().synchronize(did, handle, getId(), index);
	}

	/**
	 * Synchronize the specific DID from ID chain.
	 *
	 * @param index the DID derive index
	 * @return true if synchronized success, false if not synchronized
	 * @throws DIDResolveException if an error occurred when resolving DID
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean synchronize(int index)
			throws DIDResolveException, DIDStoreException {
		return synchronize(index, null);
	}

	/**
	 * Synchronize the specific DID from ID chain in asynchronous mode.
	 *
	 * <p>
	 * If the ConflictHandle is not set by the developers, this method will
	 * use the default ConflictHandle implementation: if conflict between
	 * the chain copy and the local copy, it will keep the local copy, but
	 * update the local metadata with the chain copy.
	 * </p>
	 *
	 * @param index the DID derive index
	 * @param handle an application defined handle to process the conflict
	 * 				 between the chain copy and the local copy
	 * @return a new CompletableStage, the result is the boolean value that
	 * 			indicate the synchronize result
	 */
	public CompletableFuture<Boolean> synchronizeAsync(int index, ConflictHandle handle) {
		CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
			try {
				return synchronize(index, handle);
			} catch (DIDResolveException | DIDStoreException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Synchronize the specific DID from ID chain in asynchronous mode.
	 *
	 * @param index the DID derive index
	 * @return a new CompletableStage, the result is the boolean value that
	 * 			indicate the synchronize result
	 */
	public CompletableFuture<Boolean> synchronizeAsync(int index) {
		return synchronizeAsync(index, null);
	}

	/**
	 * Synchronize all DIDs that derived from this RootIdentity object.
	 *
	 * <p>
	 * If the ConflictHandle is not set by the developers, this method will
	 * use the default ConflictHandle implementation: if conflict between
	 * the chain copy and the local copy, it will keep the local copy, but
	 * update the local metadata with the chain copy.
	 * </p>
	 *
	 * @param handle an application defined handle to process the conflict
	 * 				 between the chain copy and the local copy
	 * @throws DIDResolveException if an error occurred when resolving DID
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public void synchronize(ConflictHandle handle)
			throws DIDResolveException, DIDStoreException {
		log.info("Synchronize root identity {}...", getId());

		int lastIndex = getIndex() - 1;
		int blanks = 0;
		int i = 0;

		while (i < lastIndex || blanks < 20) {
			boolean exists = synchronize(i, handle);
			if (exists) {
				if (i > lastIndex)
					lastIndex = i;

				blanks = 0;
			} else {
				if (i > lastIndex)
					blanks++;
			}

			i++;
		}

		if (lastIndex >= getIndex())
			setIndex(lastIndex + 1);
	}

	/**
	 * Synchronize all DIDs that derived from this RootIdentity object.
	 *
	 * @throws DIDResolveException if an error occurred when resolving DID
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public void synchronize()
			throws DIDResolveException, DIDStoreException {
		synchronize(null);
	}

	/**
	 * Synchronize all DIDs that derived from this RootIdentity object in
	 * asynchronous mode.
	 *
	 * <p>
	 * If the ConflictHandle is not set by the developers, this method will
	 * use the default ConflictHandle implementation: if conflict between
	 * the chain copy and the local copy, it will keep the local copy, but
	 * update the local metadata with the chain copy.
	 * </p>
	 *
	 * @param handle an application defined handle to process the conflict
	 * 				 between the chain copy and the local copy
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> synchronizeAsync(ConflictHandle handle) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				synchronize(handle);
			} catch (DIDResolveException | DIDStoreException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Synchronize all DIDs that derived from this RootIdentity object in
	 * asynchronous mode.
	 *
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> synchronizeAsync() {
		return synchronizeAsync(null);
	}
}
