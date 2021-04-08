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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.elastos.did.DIDDocument.PublicKey;
import org.elastos.did.crypto.Aes256cbc;
import org.elastos.did.crypto.Base64;
import org.elastos.did.crypto.EcdsaSigner;
import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStorageException;
import org.elastos.did.exception.DIDStoreCryptoException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.MalformedExportDataException;
import org.elastos.did.exception.WrongPasswordException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.digests.MD5Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.util.encoders.Hex;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

/**
 * This class represents a storage facility for DID objects and private keys.
 *
 * The DIDStore manages different types of entries:
 * - RootIdentity
 * - DIDDocument
 * - VerifiableCredential
 * - PrivateKey
 */
public final class DIDStore {
	/**
	 * The type string for DIDStore.
	 */
	protected static final String DID_STORE_TYPE = "did:elastos:store";
	/**
	 * Current DIDStore version.
	 */
	protected static final int DID_STORE_VERSION = 3;

	private static final int CACHE_INITIAL_CAPACITY = 16;
	private static final int CACHE_MAX_CAPACITY = 128;

	private static final Object NULL = new Object();

	private static final String DID_EXPORT = "did.elastos.export/2.0";

	private Cache<Key, Object> cache;

	private DIDStorage storage;
	private Metadata metadata;

	/**
	 * the default conflict handle implementation.
	 */
	protected static final ConflictHandle defaultConflictHandle = (c, l) -> {
		l.getMetadata().setPublishTime(c.getMetadata().getPublishTime());
		l.getMetadata().setSignature(c.getMetadata().getSignature());
		return l;
	};

	private static final Logger log = LoggerFactory.getLogger(DIDStore.class);

	static class Key {
		private static final int TYPE_ROOT_IDENTITY = 0x00;
		private static final int TYPE_ROOT_IDENTITY_PRIVATEKEY = 0x01;
		private static final int TYPE_DID_DOCUMENT = 0x10;
		private static final int TYPE_DID_METADATA = 0x11;
		private static final int TYPE_DID_PRIVATEKEY = 0x12;
		private static final int TYPE_CREDENTIAL = 0x20;
		private static final int TYPE_CREDENTIAL_METADATA = 0x21;

		private int type;
		private Object id;

		private Key(int type, Object id) {
			this.type = type;
			this.id = id;
		}

		@Override
		public int hashCode() {
			return type + id.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == this)
				return true;

			if (obj instanceof Key) {
				Key key = (Key)obj;
				return type == key.type ? id.equals(key.id) : false;
			}

			return false;
		}

		public static Key forRootIdentity(String id) {
			return new Key(TYPE_ROOT_IDENTITY, id);
		}

		public static Key forRootIdentityPrivateKey(String id) {
			return new Key(TYPE_ROOT_IDENTITY_PRIVATEKEY, id);
		}

		public static Key forDidDocument(DID did) {
			return new Key(TYPE_DID_DOCUMENT, did);
		}

		public static Key forDidMetadata(DID did) {
			return new Key(TYPE_DID_METADATA, did);
		}

		private static Key forDidPrivateKey(DIDURL id) {
			return new Key(TYPE_DID_PRIVATEKEY, id);
		}

		private static Key forCredential(DIDURL id) {
			return new Key(TYPE_CREDENTIAL, id);
		}

		private static Key forCredentialMetadata(DIDURL id) {
			return new Key(TYPE_CREDENTIAL_METADATA, id);
		}
	}

	static class Metadata extends AbstractMetadata {
		private static final String TYPE = "type";
		private static final String VERSION = "version";
		private static final String FINGERPRINT = "fingerprint";
		private static final String DEFAULT_ROOT_IDENTITY = "defaultRootIdentity";

		protected Metadata(DIDStore store) {
			super(store);
			put(TYPE, DID_STORE_TYPE);
			put(VERSION, DID_STORE_VERSION);
		}

		/**
		 *  The default constructor for JSON deserialize creator.
		 */
		protected Metadata() {
			this(null);
		}

		protected String getType() {
			return get(TYPE);
		}

		public int getVersion() {
			return getInteger(VERSION);
		}

		private void setFingerprint(String fingerprint) {
			checkArgument(fingerprint != null && !fingerprint.isEmpty(), "Invalid fingerprint");

			put(FINGERPRINT, fingerprint);
		}

		public String getFingerprint() {
			return get(FINGERPRINT);
		}

		protected void setDefaultRootIdentity(String id) {
			put(DEFAULT_ROOT_IDENTITY, id);
		}

		public String getDefaultRootIdentity() {
			return get(DEFAULT_ROOT_IDENTITY);
		}

		@Override
		protected void save() {
			if (attachedStore()) {
				try {
					getStore().storage.storeMetadata(this);
				} catch (DIDStoreException ignore) {
					log.error("INTERNAL - error store metadata for DIDStore");
				}
			}
		}
	}

	/**
	 * ConflictHandle is a interface for solving the conflict,
	 * if the local document is different with the one resolved from chain.
	 */
	@FunctionalInterface
	public interface ConflictHandle {
		/**
		 * The method to merge two did document.
		 *
		 * @param chainCopy the document from chain
		 * @param localCopy the document from local device
		 * @return the merged DIDDocument object
		 */
		DIDDocument merge(DIDDocument chainCopy, DIDDocument localCopy);
	}

	/**
	 * A filter for DIDs.
	 *
	 * <p>
	 * Instances of this interface may be passed to the listDids(DIDFilter)
	 * method of the DIDStore class.
	 * </p>
	 */
	@FunctionalInterface
	public interface DIDFilter {
		/**
		 * Tests whether or not the specified DID should be included in a
		 * DIDs list.
		 *
		 * @param did the DID to be tested
		 * @return true if and only if DID should be included
		 */
		public boolean accept(DID did);
	}

	/**
	 * A filter for DIDURLs.
	 *
	 * <p>
	 * Instances of this interface may be passed to the
	 * listCredentials(CredentialFilter) method of the DIDStore class.
	 * </p>
	 */
	@FunctionalInterface
	public interface CredentialFilter {
		/**
		 * Tests whether or not the specified id should be included in a
		 * id list.
		 *
		 * @param id the DIDURL to be tested
		 * @return true if and only if DIDURL should be included
		 */
		public boolean accept(DIDURL id);
	}

	private DIDStore(int initialCacheCapacity, int maxCacheCapacity,
			DIDStorage storage) throws DIDStoreException {
		if (initialCacheCapacity < 0)
			initialCacheCapacity = 0;

		if (maxCacheCapacity < 0)
			maxCacheCapacity = 0;

		// The RemovalListener used for debug purpose.
		// TODO: comment the RemovalListener
		/*
		RemovalListener<Object, Object> listener;
		listener = new RemovalListener<Object, Object>() {
			@Override
			public void onRemoval(RemovalNotification<Object, Object> n) {
				if (n.wasEvicted()) {
					String cause = n.getCause().name();
					log.trace("Cache removed {} cause {}", n.getKey(), cause);
				}
			}
		};
		*/

		cache = CacheBuilder.newBuilder()
				.initialCapacity(initialCacheCapacity)
				.maximumSize(maxCacheCapacity)
				.softValues()
				// .removalListener(listener)
				// .recordStats()
				.build();

		this.storage = storage;
		this.metadata = storage.loadMetadata();
		this.metadata.attachStore(this);

		log.info("DID store opened: {}, cache(init:{}, max:{})",
				storage.getLocation(), initialCacheCapacity, maxCacheCapacity);
	}

	/**
	 * Open a DIDStore instance with given storage location.
	 *
	 * @param location the storage location for the DIDStore
	 * @param initialCacheCapacity the initial cache capacity
	 * @param maxCacheCapacity the maximum cache capacity
	 * @return the DIDStore object
	 * @throws DIDStoreException if an error occurred when opening the store
	 */
	public static DIDStore open(File location,
			int initialCacheCapacity, int maxCacheCapacity) throws DIDStoreException {
		checkArgument(location != null, "Invalid store location");
		checkArgument(maxCacheCapacity >= initialCacheCapacity, "Invalid cache capacity spec");

		try {
			location = location.getCanonicalFile();
		} catch (IOException e) {
			throw new IllegalArgumentException("Invalid store location", e);
		}

		DIDStorage storage = new FileSystemStorage(location);
		return new DIDStore(initialCacheCapacity, maxCacheCapacity, storage);
	}

	/**
	 * Open a DIDStore instance with given storage location.
	 *
	 * @param location the storage location for the DIDStore
	 * @param initialCacheCapacity the initial cache capacity
	 * @param maxCacheCapacity the maximum cache capacity
	 * @return the DIDStore object
	 * @throws DIDStoreException if an error occurred when opening the store
	 */
	public static DIDStore open(String location,
			int initialCacheCapacity, int maxCacheCapacity) throws DIDStoreException {
		checkArgument(location != null && !location.isEmpty(), "Invalid store location");

		return open(new File(location), initialCacheCapacity, maxCacheCapacity);
	}

	/**
	 * Open a DIDStore instance with given storage location.
	 *
	 * @param location the storage location for the DIDStore
	 * @return the DIDStore object
	 * @throws DIDStoreException if an error occurred when opening the store
	 */
	public static DIDStore open(File location) throws DIDStoreException {
		return open(location, CACHE_INITIAL_CAPACITY, CACHE_MAX_CAPACITY);
	}

	/**
	 * Open a DIDStore instance with given storage location.
	 *
	 * @param location the storage location for the DIDStore
	 * @return the DIDStore object
	 * @throws DIDStoreException if an error occurred when opening the store
	 */
	public static DIDStore open(String location) throws DIDStoreException {
		return open(location, CACHE_INITIAL_CAPACITY, CACHE_MAX_CAPACITY);
	}

	/**
	 * Close this DIDStore object.
	 */
	public void close() {
		// log.verbose("Cache statistics: {}", cache.stats().toString());
		cache.invalidateAll();
		cache = null;
		metadata = null;
		storage = null;
	}

	private static String calcFingerprint(String password) throws DIDStoreException {
		MD5Digest md5 = new MD5Digest();
		byte[] digest = new byte[md5.getDigestSize()];
		byte[] passwd = password.getBytes();
		md5.update(passwd, 0, passwd.length);
		md5.doFinal(digest, 0);
		md5.reset();

		try {
			byte[] cipher = Aes256cbc.encrypt(digest, password);
			md5.update(cipher, 0, cipher.length);
			md5.doFinal(digest, 0);

			return Hex.toHexString(digest);
		} catch (CryptoException e) {
			throw new DIDStoreCryptoException("Calculate fingerprint error.", e);
		}
	}

	private static String encryptToBase64(byte[] input, String passwd)
			throws DIDStoreException {
		try {
			byte[] cipher = Aes256cbc.encrypt(input, passwd);

			return Base64.encodeToString(cipher,
					Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
		} catch (CryptoException e) {
			throw new DIDStoreCryptoException("Encrypt data error.", e);
		}
	}

	private static byte[] decryptFromBase64(String input, String passwd)
			throws DIDStoreException {
		try {
			byte[] cipher = Base64.decode(input,
					Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);

			return Aes256cbc.decrypt(cipher, passwd);
		} catch (CryptoException e) {
			throw new WrongPasswordException("Decrypt private key error.", e);
		}
	}

	private static String reEncrypt(String secret, String oldpass, String newpass)
			throws DIDStoreException {
		byte[] plain = decryptFromBase64(secret, oldpass);
		String newSecret = encryptToBase64(plain, newpass);
		Arrays.fill(plain, (byte)0);
		return newSecret;
	}

	private String encrypt(byte[] input, String passwd) throws DIDStoreException {
		String fingerprint = metadata.getFingerprint();
		String currentFingerprint = calcFingerprint(passwd);

		if (fingerprint != null && !currentFingerprint.equals(fingerprint))
			throw new WrongPasswordException("Password mismatched with previous password.");

		String result = encryptToBase64(input, passwd);

		if (fingerprint == null || fingerprint.isEmpty())
			metadata.setFingerprint(currentFingerprint);

		return result;
	}

	private byte[] decrypt(String input, String passwd) throws DIDStoreException {
		String fingerprint = metadata.getFingerprint();
		String currentFingerprint = calcFingerprint(passwd);

		byte[] result = decryptFromBase64(input, passwd);

		if (fingerprint == null || fingerprint.isEmpty())
			metadata.setFingerprint(currentFingerprint);

		return result;
	}

	/**
	 * Save the RootIdentity object with private keys to this DID store.
	 *
	 * @param identity an RootIdentity object
	 * @param storepass the password for this DID store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected void storeRootIdentity(RootIdentity identity, String storepass)
			throws DIDStoreException {
		checkArgument(identity != null, "Invalid identity");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		String encryptedMnemonic = null;
		if (identity.getMnemonic() != null)
			encryptedMnemonic = encrypt(identity.getMnemonic().getBytes(), storepass);

		String encryptedPrivateKey = encrypt(identity.getRootPrivateKey().serialize(), storepass);

		String publicKey = identity.getPreDerivedPublicKey().serializePublicKeyBase58();

		storage.storeRootIdentity(identity.getId(), encryptedMnemonic,
				encryptedPrivateKey, publicKey, identity.getIndex());

		if (metadata.getDefaultRootIdentity() == null)
			metadata.setDefaultRootIdentity(identity.getId());

		cache.invalidate(Key.forRootIdentity(identity.getId()));
		cache.invalidate(Key.forRootIdentityPrivateKey(identity.getId()));
	}

	/**
	 * Save the RootIdentity object to this DID store(Update the derive index
	 * only).
	 *
	 * @param identity an RootIdentity object
	 * @param storepass the password for this DID store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected void storeRootIdentity(RootIdentity identity)
			throws DIDStoreException {
		checkArgument(identity != null, "Invalid identity");
		storage.updateRootIdentityIndex(identity.getId(), identity.getIndex());
	}

	/**
	 * Set the identity as the default RootIdentity of the DIDStore.
	 *
	 * @param identity a RootIdentity object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected void setDefaultRootIdentity(RootIdentity identity) throws DIDStoreException {
		checkArgument(identity != null, "Invalid identity");

		if (!containsRootIdentity(identity.getId()))
			throw new IllegalArgumentException("Invalid identity, not exists in the store");

		metadata.setDefaultRootIdentity(identity.getId());
	}

	/**
	 * Load a RootIdentity object from this DIDStore.
	 *
	 * @param id the id of the RootIdentity
	 * @return the RootIdentity object, null if the identity not exists
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public RootIdentity loadRootIdentity(String id) throws DIDStoreException {
		checkArgument(id != null && !id.isEmpty(), "Invalid id");

		try {
			Object value = cache.get(Key.forRootIdentity(id), new Callable<Object>() {
				@Override
				public Object call() throws DIDStoreException {
					RootIdentity identity = storage.loadRootIdentity(id);
					if (identity != null) {
						identity.setMetadata(loadRootIdentityMetadata(id));
						return identity;
					} else {
						return NULL;
					}
				}
			});

			return value == NULL ? null : (RootIdentity)value;
		} catch (ExecutionException e) {
			throw new DIDStoreException("Load root identity failed: " + id, e);
		}
	}

	/**
	 * Load the default RootIdentity object from this DIDStore.
	 *
	 * @return the default RootIdentity object, null if the identity exists
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public RootIdentity loadRootIdentity() throws DIDStoreException {
		String id = metadata.getDefaultRootIdentity();
		if (id == null || id.isEmpty()) {
			List<RootIdentity> ids = storage.listRootIdentities();
			if (ids.size() != 1) {
				return null;
			} else {
				RootIdentity identity = ids.get(0);
				metadata.setDefaultRootIdentity(identity.getId());
				return identity;
			}
		}

		return loadRootIdentity(id);
	}

	/**
	 * Check whether the RootIdentity exists in this DIDStore.
	 *
	 * @param id the id of the RootIdentity to be check
	 * @return true if exists else false
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean containsRootIdentity(String id) throws DIDStoreException {
		return storage.loadRootIdentity(id) != null;
	}

	/**
	 * Export the mnemonic of the specific RootIdentity from this DIDStore.
	 *
	 * @param id the id of the RootIdentity
	 * @param storepass the password for DIDStore
	 * @return the mnemonic string, null if the identity not exists or does
	 * 		   not have mnemonic
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected String exportRootIdentityMnemonic(String id, String storepass)
			throws DIDStoreException {
		checkArgument(id != null && !id.isEmpty(), "Invalid id");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		String encryptedMnemonic = storage.loadRootIdentityMnemonic(id);
		if (encryptedMnemonic != null)
			return new String(decrypt(encryptedMnemonic, storepass));
		else
			return null;
	}

	/**
	 * Check whether the RootIdentity has mnemonic.
	 *
	 * @param id the id of the RootIdentity
	 * @return true if exists else false
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected boolean containsRootIdentityMnemonic(String id) throws DIDStoreException {
		checkArgument(id != null && !id.isEmpty(), "Invalid id");

		String encryptedMnemonic = storage.loadRootIdentityMnemonic(id);
		return encryptedMnemonic != null;
	}

	private HDKey loadRootIdentityPrivateKey(String id, String storepass)
			throws DIDStoreException {
		try {
			Object value = cache.get(Key.forRootIdentityPrivateKey(id), new Callable<Object>() {
				@Override
				public Object call() throws DIDStorageException {
					String encryptedKey = storage.loadRootIdentityPrivateKey(id);
					return encryptedKey != null ? encryptedKey : NULL;			    }
			});

			if (value != NULL) {
				byte[] keyData = decrypt((String)value, storepass);
				return HDKey.deserialize(keyData);
			} else {
				return null;
			}
		} catch (ExecutionException e) {
			throw new DIDStoreException("Load root identity private key failed: " + id, e);
		}
	}

	HDKey derive(String id, String path, String storepass)
			throws DIDStoreException {
		checkArgument(id != null && !id.isEmpty(), "Invalid identity");
		checkArgument(path != null && !path.isEmpty(), "Invalid path");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		HDKey rootPrivateKey = loadRootIdentityPrivateKey(id, storepass);
		HDKey key = rootPrivateKey.derive(path);
		rootPrivateKey.wipe();

		return key;
	}

	/**
	 * Delete the specific RootIdentity object from this store.
	 *
	 * @param id the id of RootIdentity object
	 * @return true if the identity exists and delete successful; false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean deleteRootIdentity(String id) throws DIDStoreException {
		checkArgument(id != null && !id.isEmpty(), "Invalid id");

		boolean success = storage.deleteRootIdentity(id);
		if (success) {
			if (metadata.getDefaultRootIdentity() != null &&
					metadata.getDefaultRootIdentity().equals(id))
			metadata.setDefaultRootIdentity(null);

			cache.invalidate(Key.forRootIdentity(id));
			cache.invalidate(Key.forRootIdentityPrivateKey(id));
		}

		return success;
	}

	/**
	 * List all RootIdentity object from this store.
	 *
	 * @return an array of RootIdentity objects
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public List<RootIdentity> listRootIdentities() throws DIDStoreException {
		return Collections.unmodifiableList(storage.listRootIdentities());
	}

	/**
	 * Check whether the this store has RootIdentity objects.
	 *
	 * @return true if the store has RootIdentity objects else false
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean containsRootIdentities() throws DIDStoreException {
		return storage.containsRootIdenities();
	}

	/**
	 * Save the RootIdentity metadata to this store.
	 *
	 * @param id the id of the RootIdentity object
	 * @param metadata a RootIdentity.Metadata object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected void storeRootIdentityMetadata(String id, RootIdentity.Metadata metadata)
			throws DIDStoreException {
		checkArgument(id != null && !id.isEmpty(), "Invalid id");
		checkArgument(metadata != null, "Invalid metadata");

		storage.storeRootIdentityMetadata(id, metadata);
	}

	/**
	 * Read the RootIdentity metadata from this store.
	 *
	 * @param id the id of the RootIdentity object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected RootIdentity.Metadata loadRootIdentityMetadata(String id)
			throws DIDStoreException {
		checkArgument(id != null && !id.isEmpty(), "Invalid id");

		RootIdentity.Metadata metadata = storage.loadRootIdentityMetadata(id);
		if (metadata != null) {
			metadata.setId(id);
			metadata.attachStore(this);
		} else {
			metadata = new RootIdentity.Metadata(id, this);
		}

		return metadata;
	}

	/**
	 * Save the DID document to this store.
	 *
	 * @param doc the DIDDocument object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public void storeDid(DIDDocument doc) throws DIDStoreException {
		checkArgument(doc != null, "Invalid doc");

		storage.storeDid(doc);
		if (doc.getStore() != this) {
			DIDMetadata metadata = loadDidMetadata(doc.getSubject());
			doc.getMetadata().merge(metadata);
			storeDidMetadata(doc.getSubject(), doc.getMetadata());

			doc.getMetadata().attachStore(this);
		}

		for (VerifiableCredential vc : doc.getCredentials())
			storeCredential(vc);

		cache.put(Key.forDidDocument(doc.getSubject()), doc);
	}

	/**
	 * Read the specific DID document from this store.
	 *
	 * @param did the DID to be load
	 * @return the DIDDocument object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument loadDid(DID did) throws DIDStoreException {
		checkArgument(did != null, "Invalid did");

		try {
			Object value = cache.get(Key.forDidDocument(did), new Callable<Object>() {
				@Override
				public Object call() throws DIDStoreException {
					DIDDocument doc = storage.loadDid(did);
					if (doc != null) {
						doc.setMetadata(loadDidMetadata(did));
						return doc;
					} else {
						return NULL;
					}
				}
			});

			return value == NULL ? null : (DIDDocument)value;
		} catch (ExecutionException e) {
			throw new DIDStoreException("Load did document failed: " + did, e);
		}
	}

	/**
	 * Read the specific DID document from this store.
	 *
	 * @param did the DID to be load
	 * @return the DIDDocument object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public DIDDocument loadDid(String did) throws DIDStoreException {
		return loadDid(DID.valueOf(did));
	}

	/**
	 * Check if this store contains the specific DID.
	 *
	 * @param did the specified DID
	 * @return true if the store contains this DID, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean containsDid(DID did) throws DIDStoreException {
		checkArgument(did != null, "Invalid did");
		return loadDid(did) != null;
	}

	/**
	 * Check if this store contains the specific DID.
	 *
	 * @param did the specified DID
	 * @return true if the store contains this DID, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean containsDid(String did) throws DIDStoreException {
		return containsDid(DID.valueOf(did));
	}

	/**
	 * Save the DID Metadata to this store.
	 *
	 * @param did the owner of the metadata object
	 * @param metadata the DID metadata object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected void storeDidMetadata(DID did, DIDMetadata metadata)
			throws DIDStoreException {
		checkArgument(did != null, "Invalid did");
		checkArgument(metadata != null, "Invalid metadata");

		storage.storeDidMetadata(did, metadata);
		metadata.attachStore(this);

		cache.put(Key.forDidMetadata(did), metadata);
	}

	/**
	 * Read the specific DID metadata object for this store.
	 *
	 * @param did a DID to be load
	 * @return the DID metadata object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected DIDMetadata loadDidMetadata(DID did) throws DIDStoreException {
		checkArgument(did != null, "Invalid did");

		try {
			Object value = cache.get(Key.forDidMetadata(did) , new Callable<Object>() {
				@Override
				public Object call() throws DIDStorageException {
					DIDMetadata metadata = storage.loadDidMetadata(did);
					if (metadata != null) {
						metadata.setDid(did);
						metadata.attachStore(DIDStore.this);
					} else {
						metadata = new DIDMetadata(did, DIDStore.this);
					}

					return metadata;
				}
			});

			return value == NULL ? null : (DIDMetadata)value;
		} catch (ExecutionException e) {
			throw new DIDStoreException("Load did metadata failed: " + did, e);
		}
	}

	/**
	 * Delete the specific DID from this store.
	 *
	 * <p>
	 * When delete the DID, all private keys, credentials that owned by this
	 * DID will also be deleted.
	 * </p>
	 *
	 * @param did the DID to be delete
	 * @return true if the DID exist and deleted successful, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean deleteDid(DID did) throws DIDStoreException {
		checkArgument(did != null, "Invalid did");

		boolean success = storage.deleteDid(did);

		if (success) {
			cache.invalidate(Key.forDidDocument(did));
			cache.invalidate(Key.forDidMetadata(did));

			// invalidate every thing belongs to this did
			for (Key key : cache.asMap().keySet()) {
				if (key.id instanceof DIDURL) {
					DIDURL id = (DIDURL)key.id;
					if (id.getDid().equals(did))
						cache.invalidate(key);
				}
			}
		}

		return success;
	}

	/**
	 * Delete the specific DID from this store.
	 *
	 * <p>
	 * When delete the DID, all private keys, credentials that owned by this
	 * DID will also be deleted.
	 * </p>
	 *
	 * @param did the DID to be delete
	 * @return true if the DID exist and deleted successful, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean deleteDid(String did) throws DIDStoreException {
		return deleteDid(DID.valueOf(did));
	}

	/**
	 * List all DIDs from this store.
	 *
	 * @return an array of DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public List<DID> listDids() throws DIDStoreException {
		List<DID> dids = storage.listDids();
		for (DID did : dids) {
			DIDMetadata metadata = loadDidMetadata(did);
			did.setMetadata(metadata);
		}

		return Collections.unmodifiableList(dids);
	}

	/**
	 * List all DIDs that satisfy the specified filter from this store.
	 *
	 * @param filter a DID filter
	 * @return an array of DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public List<DID> listDids(DIDFilter filter) throws DIDStoreException {
		List<DID> dids = listDids();

		if (filter != null) {
			List<DID> dest = new ArrayList<DID>();

			for (DID did : dids) {
				if (filter.accept(did))
					dest.add(did);
			}

			dids = dest;
		}

		return Collections.unmodifiableList(dids);
	}

	/**
	 * Save the credential object to this store.
	 *
	 * @param credential a VerifiableCredential object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public void storeCredential(VerifiableCredential credential)
			throws DIDStoreException {
		checkArgument(credential != null, "Invalid credential");

		storage.storeCredential(credential);
		if (credential.getMetadata().getStore() != this) {
			CredentialMetadata metadata = loadCredentialMetadata(credential.getId());
			credential.getMetadata().merge(metadata);
			storeCredentialMetadata(credential.getId(), credential.getMetadata());

			credential.getMetadata().attachStore(this);
		}

		cache.put(Key.forCredential(credential.getId()), credential);
	}

	/**
	 * Read the specific credential object from this store.
	 *
	 * @param id the credential id
	 * @return the VerifiableCredential object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public VerifiableCredential loadCredential(DIDURL id)
			throws DIDStoreException {
		checkArgument(id != null, "Invalid credential id");

		try {
			Object value = cache.get(Key.forCredential(id), new Callable<Object>() {
				@Override
				public Object call() throws DIDStoreException {
					VerifiableCredential vc = storage.loadCredential(id);
					if (vc != null) {
						vc.setMetadata(loadCredentialMetadata(id));
						return vc;
					} else {
						return NULL;
					}
				}
			});

			return value == NULL ? null : (VerifiableCredential)value;
		} catch (ExecutionException e) {
			throw new DIDStoreException("Load credential failed: " + id, e);
		}
	}

	/**
	 * Read the specific credential object from this store.
	 *
	 * @param id the credential id
	 * @return the VerifiableCredential object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public VerifiableCredential loadCredential(String id)
			throws DIDStoreException {
		return loadCredential(DIDURL.valueOf(id));
	}

	/**
	 * Check whether this store contains the specific credential.
	 *
	 * @param id the credential id
	 * @return true if the store contains this credential, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean containsCredential(DIDURL id)
			throws DIDStoreException {
		checkArgument(id != null, "Invalid credential id");
		return loadCredential(id) != null;
	}

	/**
	 * Check whether this store contains the specific credential.
	 *
	 * @param id the credential id
	 * @return true if the store contains this credential, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean containsCredential(String id)
			throws DIDStoreException {
		return containsCredential(DIDURL.valueOf(id));
	}

	/**
	 * Check whether this store contains the credentials that owned by the
	 * specific DID.
	 *
	 * @param did the credential owner's DID
	 * @return true if the store contains this credential, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean containsCredentials(DID did) throws DIDStoreException {
		checkArgument(did != null, "Invalid did");
		return storage.containsCredentials(did);
	}

	/**
	 * Check whether this store contains the credentials that owned by the
	 * specific DID.
	 *
	 * @param did the credential owner's DID
	 * @return true if the store contains this credential, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean containsCredentials(String did) throws DIDStoreException {
		return containsCredentials(DID.valueOf(did));
	}

	/**
	 * Save the credential's metadata to this store.
	 *
	 * @param id the credential id
	 * @param metadata the credential metadata object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected void storeCredentialMetadata(DIDURL id,
			CredentialMetadata metadata) throws DIDStoreException {
		checkArgument(id != null, "Invalid credential id");
		checkArgument(metadata != null, "Invalid credential metadata");

		storage.storeCredentialMetadata(id, metadata);
		metadata.attachStore(this);

		cache.put(Key.forCredentialMetadata(id), metadata);
	}

	/**
	 * Read the credential's metadata from this store.
	 *
	 * @param id the credential id
	 * @return the credential metadata object
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected CredentialMetadata loadCredentialMetadata(DIDURL id)
			throws DIDStoreException {
		checkArgument(id != null, "Invalid credential id");

		try {
			Object value = cache.get(Key.forCredentialMetadata(id), new Callable<Object>() {
				@Override
				public Object call() throws DIDStorageException {
					CredentialMetadata metadata = storage.loadCredentialMetadata(id);
					if (metadata != null) {
						metadata.setId(id);
						metadata.attachStore(DIDStore.this);
					} else {
						metadata = new CredentialMetadata(id, DIDStore.this);
					}

					return metadata;
				}
			});

			return value == NULL ? null : (CredentialMetadata)value;
		} catch (ExecutionException e) {
			throw new DIDStoreException("Load Credential metadata failed: " + id, e);
		}
	}

	/**
	 * Delete the specific credential from this store.
	 *
	 * @param id the credential id to be delete
	 * @return true if the credential exist and deleted successful, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean deleteCredential(DIDURL id) throws DIDStoreException {
		checkArgument(id != null, "Invalid credential id");

		boolean success = storage.deleteCredential(id);
		if (success) {
			cache.invalidate(Key.forCredential(id));
			cache.invalidate(Key.forCredentialMetadata(id));
		}

		return success;
	}

	/**
	 * Delete the specific credential from this store.
	 *
	 * @param id the credential id to be delete
	 * @return true if the credential exist and deleted successful, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean deleteCredential(String id) throws DIDStoreException {
		return deleteCredential(DIDURL.valueOf(id));
	}

	/**
	 * List all credentials that owned the specific DID.
	 *
	 * @param did the credential owner's DID
	 * @return an array of DIDURL denoting the credentials
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public List<DIDURL> listCredentials(DID did) throws DIDStoreException {
		checkArgument(did != null, "Invalid did");

		List<DIDURL> ids = storage.listCredentials(did);
		for (DIDURL id : ids) {
			CredentialMetadata metadata = loadCredentialMetadata(id);
			id.setMetadata(metadata);
		}

		return Collections.unmodifiableList(ids);
	}

	/**
	 * List all credentials that owned the specific DID.
	 *
	 * @param did the credential owner's DID
	 * @return an array of DIDURL denoting the credentials
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public List<DIDURL> listCredentials(String did) throws DIDStoreException {
		return listCredentials(DID.valueOf(did));
	}

	/**
	 * List all credentials that owned the specific DID and satisfy the
	 * specified filter from this store.
	 *
	 * @param did the credential owner's DID
	 * @param filter a credential filter
	 * @return an array of DIDURL denoting the credentials
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public List<DIDURL> listCredentials(DID did, CredentialFilter filter)
			throws DIDStoreException {
		checkArgument(did != null, "Invalid did");

		List<DIDURL> vcs = listCredentials(did);

		if (filter != null) {
			List<DIDURL> dest = new ArrayList<DIDURL>();

			for (DIDURL id : vcs) {
				if (filter.accept(id))
					dest.add(id);
			}

			vcs = dest;
		}

		return Collections.unmodifiableList(vcs);
	}

	/**
	 * List all credentials that owned the specific DID and satisfy the
	 * specified filter from this store.
	 *
	 * @param did the credential owner's DID
	 * @param filter a credential filter
	 * @return an array of DIDURL denoting the credentials
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public List<DIDURL> listCredentials(String did, CredentialFilter filter)
			throws DIDStoreException {
		return listCredentials(DID.valueOf(did), filter);
	}

	/**
	 * Save the DID's private key to the store, the private key will be encrypt
	 * using the store password.
	 *
	 * @param id the private key id
	 * @param privateKey the binary extended private key
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public void storePrivateKey(DIDURL id, byte[] privateKey,
			String storepass) throws DIDStoreException {
		checkArgument(id != null, "Invalid private key id");
		checkArgument(privateKey != null && privateKey.length != 0, "Invalid private key");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		String encryptedKey = encrypt(privateKey, storepass);
		storage.storePrivateKey(id, encryptedKey);

		cache.put(Key.forDidPrivateKey(id), encryptedKey);
	}

	/**
	 * Save the DID's private key to the store, the private key will be encrypt
	 * using the store password.
	 *
	 * @param id the private key id
	 * @param privateKey the binary extended private key
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public void storePrivateKey(String id, byte[] privateKey,
			String storepass) throws DIDStoreException {
		storePrivateKey(DIDURL.valueOf(id), privateKey, storepass);
	}

	private String loadPrivateKey(DIDURL id) throws DIDStoreException {
		try {
			Object value = cache.get(Key.forDidPrivateKey(id), new Callable<Object>() {
				@Override
				public Object call() throws DIDStoreException {
					String encryptedKey = storage.loadPrivateKey(id);
					return encryptedKey != null ? encryptedKey : NULL;
				}
			});

			return value == NULL ? null : (String)value;
		} catch (ExecutionException e) {
			throw new DIDStoreException("Load did private key failed: " + id, e);
		}
	}

	byte[] loadPrivateKey(DIDURL id, String storepass)
			throws DIDStoreException {
		checkArgument(id != null, "Invalid private key id");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		String encryptedKey = loadPrivateKey(id);
		if (encryptedKey == null) {
			// fail-back to lazy private key generation
			return RootIdentity.lazyCreateDidPrivateKey(id, this, storepass);
		} else {
			return decrypt(encryptedKey, storepass);
		}
	}

	/**
	 * Check if this store contains the specific private key.
	 *
	 * @param id the key id
	 * @return true if this store contains the specific key, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean containsPrivateKey(DIDURL id) throws DIDStoreException {
		checkArgument(id != null, "Invalid private key id");
		return loadPrivateKey(id) != null;
	}

	/**
	 * Check if this store contains the specific private key.
	 *
	 * @param id the key id
	 * @return true if this store contains the specific key, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean containsPrivateKey(String id) throws DIDStoreException {
		return containsPrivateKey(DIDURL.valueOf(id));
	}

	/**
	 * Check if this store contains the private keys that owned by the
	 * specific DID.
	 *
	 * @param did the owner's DID
	 * @return true if this store contains the private keys owned by the the
	 * 		   DID, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean containsPrivateKeys(DID did) throws DIDStoreException {
		checkArgument(did != null, "Invalid did");
		return storage.containsPrivateKeys(did);
	}

	/**
	 * Check if this store contains the private keys that owned by the
	 * specific DID.
	 *
	 * @param did the owner's DID
	 * @return true if this store contains the private keys owned by the the
	 * 		   DID, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean containsPrivateKeys(String did) throws DIDStoreException {
		return containsPrivateKeys(DID.valueOf(did));
	}

	/**
	 * Delete the specific private key from this store.
	 *
	 * @param id the key id
	 * @return true if the private key exist and deleted successful, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean deletePrivateKey(DIDURL id) throws DIDStoreException {
		checkArgument(id != null, "Invalid private key id");

		boolean success = storage.deletePrivateKey(id);
		if (success)
			cache.invalidate(Key.forDidPrivateKey(id));

		return success;
	}

	/**
	 * Delete the specific private key from this store.
	 *
	 * @param id the key id
	 * @return true if the private key exist and deleted successful, false otherwise
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public boolean deletePrivateKey(String id) throws DIDStoreException {
		return deletePrivateKey(DIDURL.valueOf(id));
	}

	/**
	 * Sign the digest using the specified key.
	 *
	 * @param id the key id
	 * @param storepass the password for this store
	 * @param digest the binary digest in bytes array
	 * @return the base64(URL safe) encoded signature string
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected String sign(DIDURL id, String storepass, byte[] digest)
			throws DIDStoreException {
		checkArgument(id != null, "Invalid private key id");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkArgument(digest != null && digest.length > 0, "Invalid digest");

		HDKey key = HDKey.deserialize(loadPrivateKey(id, storepass));
		byte[] sig = EcdsaSigner.sign(key.getPrivateKeyBytes(), digest);
		key.wipe();

		return Base64.encodeToString(sig,
				Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
	}

	/**
	 * Change the password for this store.
	 *
	 * @param oldPassword the old password
	 * @param newPassword the new password
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public void changePassword(String oldPassword, String newPassword)
			throws DIDStoreException {
		checkArgument(oldPassword != null && !oldPassword.isEmpty(), "Invalid old password");
		checkArgument(newPassword != null && !newPassword.isEmpty(), "Invalid new password");

		storage.changePassword((data) -> {
			return DIDStore.reEncrypt(data, oldPassword, newPassword);
		});

		metadata.setFingerprint(calcFingerprint(newPassword));
		cache.invalidateAll();
	}

	/**
	 *
	 * @param handle
	 * @throws DIDResolveException
	 * @throws DIDStoreException
	 */

	/**
	 * Synchronize all RootIdentities, DIDs and credentials in this store.
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
	 * @throws DIDResolveException if an error occurred when resolving DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public void synchronize(ConflictHandle handle)
			throws DIDResolveException, DIDStoreException {

		if (handle == null)
			handle = defaultConflictHandle;

		List<RootIdentity> identities = storage.listRootIdentities();
		for (RootIdentity identity : identities) {
			identity.synchronize(handle);
		}

		List<DID> dids = storage.listDids();
		for (DID did : dids) {
			DIDDocument localDoc = storage.loadDid(did);
			if (localDoc.isCustomizedDid()) {
				DIDDocument resolvedDoc = did.resolve();
				if (resolvedDoc == null)
					continue;

				DIDDocument finalDoc = resolvedDoc;

				localDoc.getMetadata().detachStore();

				if (localDoc.getSignature().equals(resolvedDoc.getSignature()) ||
						(localDoc.getMetadata().getSignature() != null &&
						localDoc.getProof().getSignature().equals(
								localDoc.getMetadata().getSignature()))) {
					finalDoc.getMetadata().merge(localDoc.getMetadata());
				} else {
					log.debug("{} on-chain copy conflict with local copy.",
							did.toString());

					// Local copy was modified
					finalDoc = handle.merge(resolvedDoc, localDoc);
					if (finalDoc == null || !finalDoc.getSubject().equals(did)) {
						log.error("Conflict handle merge the DIDDocument error.");
						throw new DIDStoreException("deal with local modification error.");
					} else {
						log.debug("Conflict handle return the final copy.");
					}
				}

				storage.storeDid(finalDoc);
			}

			List<DIDURL> vcIds = storage.listCredentials(did);
			for (DIDURL vcId : vcIds) {
				VerifiableCredential localVc = storage.loadCredential(vcId);

				VerifiableCredential resolvedVc = VerifiableCredential.resolve(vcId, localVc.getIssuer());
				if (resolvedVc == null)
					continue;

				resolvedVc.getMetadata().merge(localVc.getMetadata());
				storage.storeCredential(resolvedVc);
			}
		}
	}

	/**
	 * Synchronize all RootIdentities, DIDs and credentials in this store.
	 *
	 * @throws DIDResolveException if an error occurred when resolving DIDs
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	public void synchronize() throws DIDResolveException, DIDStoreException {
		synchronize(null);
	}

	/**
	 * Synchronize all RootIdentities, DIDs and credentials in
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
	 * Synchronize all RootIdentities, DIDs and credentials in
	 * asynchronous mode.
	 *
	 * @return a new CompletableStage
	 */
	public CompletableFuture<Void> synchronizeAsync() {
		return synchronizeAsync(null);
	}

	@JsonPropertyOrder({ "type", "id", "document", "credential", "privatekey",
						 "created", "fingerprint" })
	@JsonInclude(Include.NON_NULL)
	static class DIDExport extends DIDEntity<DIDExport> {
		@JsonProperty("type")
		private String type;
		@JsonProperty("id")
		private DID id;
		@JsonProperty("document")
		private Document document;
		@JsonProperty("credential")
		private List<Credential> credentials;
		@JsonProperty("privatekey")
		private List<PrivateKey> privatekeys;
		@JsonProperty("created")
		private Date created;
		@JsonProperty("fingerprint")
		private String fingerprint;

		@JsonPropertyOrder({ "content", "metadata" })
		static class Document {
			@JsonProperty("content")
			private DIDDocument content;
			@JsonProperty("metadata")
			private DIDMetadata metadata;

			@JsonCreator
			protected Document(@JsonProperty(value = "content", required = true) DIDDocument content,
					@JsonProperty(value = "metadata") DIDMetadata metadata) {
				this.content = content;
				this.metadata = metadata;
			}
		}

		@JsonPropertyOrder({ "content", "metadata" })
		static class Credential {
			@JsonProperty("content")
			private VerifiableCredential content;
			@JsonProperty("metadata")
			private CredentialMetadata metadata;

			@JsonCreator
			protected Credential(@JsonProperty(value = "content", required = true) VerifiableCredential content,
					@JsonProperty(value = "metadata") CredentialMetadata metadata) {
				this.content = content;
				this.metadata = metadata;
			}
		}

		@JsonPropertyOrder({ "id", "key" })
		static class PrivateKey {
			@JsonProperty("id")
			private DIDURL id;
			@JsonProperty("key")
			private String key;

			@JsonCreator
			protected PrivateKey(@JsonProperty(value = "id", required = true) DIDURL id) {
				this.id = id;
			}

			public DIDURL getId() {
				return id;
			}

			public void setId(DIDURL id) {
				this.id = id;
			}

			public String getKey(String exportpass, String storepass)
					throws DIDStoreException {
				return reEncrypt(key, exportpass, storepass);
			}

			public void setKey(String key, String storepass, String exportpass)
					throws DIDStoreException {
				this.key = reEncrypt(key, storepass, exportpass);
			}
		}

		@JsonCreator
		protected DIDExport(@JsonProperty(value = "type", required = true) String type,
				@JsonProperty(value = "id", required = true) DID id) {
			if (type == null)
				throw new IllegalArgumentException("Invalid export type");

			this.type = type;
			this.id = id;
		}

		public DID getId() {
			return id;
		}

		public DIDDocument getDocument() {
			return document.content;
		}

		public void setDocument(DIDDocument doc) {
			this.document = new Document(doc,
					doc.getMetadata().isEmpty() ? null : doc.getMetadata());
		}

		public List<VerifiableCredential> getCredentials() {
			if (credentials == null)
				return Collections.emptyList();

			List<VerifiableCredential> vcs = new ArrayList<VerifiableCredential>();
			for (Credential cred : credentials)
				vcs.add(cred.content);

			return vcs;
		}

		public void addCredential(VerifiableCredential credential) {
			if (this.credentials == null)
				this.credentials = new ArrayList<Credential>();

			this.credentials.add(new Credential(credential,
					credential.getMetadata().isEmpty() ? null : credential.getMetadata()));
		}

		public List<PrivateKey> getPrivateKeys() {
			return privatekeys != null ? privatekeys : Collections.emptyList();
		}

		public void addPrivatekey(DIDURL id, String privatekey, String storepass,
				String exportpass) throws DIDStoreException {
			if (this.privatekeys == null)
				this.privatekeys = new ArrayList<PrivateKey>();

			PrivateKey sk = new PrivateKey(id);
			sk.setKey(privatekey, storepass, exportpass);
			this.privatekeys.add(sk);
		}

		private String calculateFingerprint(String exportpass) {
			SHA256Digest sha256 = new SHA256Digest();
			byte[] bytes = exportpass.getBytes();
			sha256.update(bytes, 0, bytes.length);

			bytes = type.getBytes();
			sha256.update(bytes, 0, bytes.length);

			bytes = id.toString().getBytes();
			sha256.update(bytes, 0, bytes.length);

			bytes = document.content.toString(true).getBytes();
			sha256.update(bytes, 0, bytes.length);

			if (document.metadata != null) {
				bytes = document.metadata.toString(true).getBytes();
				sha256.update(bytes, 0, bytes.length);
			}

			if (credentials != null && credentials.size() > 0) {
				for (Credential cred : credentials) {
					bytes = cred.content.toString(true).getBytes();
					sha256.update(bytes, 0, bytes.length);

					if (cred.metadata != null) {
						bytes = cred.metadata.toString(true).getBytes();
						sha256.update(bytes, 0, bytes.length);
					}
				}
			}

			if (privatekeys != null && privatekeys.size() > 0) {
				for (PrivateKey sk : privatekeys) {
					bytes = sk.id.toString().getBytes();
					sha256.update(bytes, 0, bytes.length);

					bytes = sk.key.getBytes();
					sha256.update(bytes, 0, bytes.length);
				}
			}

			bytes = dateFormat.format(created).getBytes();
			sha256.update(bytes, 0, bytes.length);

			byte digest[] = new byte[32];
			sha256.doFinal(digest, 0);
			return Base64.encodeToString(digest,
					Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
		}

		public DIDExport seal(String exportpass) {
			Calendar now = Calendar.getInstance();
			now.set(Calendar.MILLISECOND, 0);
			this.created = now.getTime();
			fingerprint = calculateFingerprint(exportpass);
			return this;
		}

		public void verify(String exportpass) throws MalformedExportDataException {
			if (!fingerprint.equals(calculateFingerprint(exportpass)))
				throw new MalformedExportDataException(
							"Invalid export data, fingerprint mismatch.");
		}

		@Override
		protected void sanitize() throws MalformedExportDataException {
			if (type == null || !type.equals(DID_EXPORT))
				throw new MalformedExportDataException(
						"Invalid export data, unknown type.");

			if (created == null)
				throw new MalformedExportDataException(
						"Invalid export data, missing created time.");

			if (id == null)
				throw new MalformedExportDataException(
						"Invalid export data, missing id.");

			if (document == null || document.content == null)
				throw new MalformedExportDataException(
						"Invalid export data, missing document.");
			document.content.setMetadata(document.metadata);

			if (credentials != null) {
				for (Credential cred : credentials) {
					if (cred == null || cred.content == null)
						throw new MalformedExportDataException(
								"Invalid export data, invalid credential.");

					cred.content.setMetadata(cred.metadata);
				}
			}

			if (privatekeys != null) {
				for (PrivateKey sk : privatekeys) {
					if (sk == null || sk.id == null || sk.key == null || sk.key.isEmpty())
						throw new MalformedExportDataException(
								"Invalid export data, invalid privatekey.");
				}
			}

			if (fingerprint == null || fingerprint.isEmpty())
				throw new MalformedExportDataException(
						"Invalid export data, missing fingerprint.");
		}
	}

	private DIDExport exportDid(DID did, String password, String storepass)
			throws DIDStoreException, IOException {
		// All objects should load directly from storage,
		// avoid affects the cached objects.

		DIDDocument doc = storage.loadDid(did);
		if (doc == null)
			throw new DIDStoreException("Export DID " + did + " failed, not exist.");

		doc.setMetadata(storage.loadDidMetadata(did));

		log.debug("Exporting {}...", did.toString());

		DIDExport de = new DIDExport(DID_EXPORT, did);
		de.setDocument(doc);

		if (storage.containsCredentials(did)) {
			List<DIDURL> ids = new ArrayList<DIDURL>(listCredentials(did));
			Collections.sort(ids);
			for (DIDURL id : ids) {
				log.debug("Exporting credential {}...", id.toString());

				VerifiableCredential vc = storage.loadCredential(id);
				vc.setMetadata(storage.loadCredentialMetadata(id));
				de.addCredential(vc);
			}
		}

		if (storage.containsPrivateKeys(did)) {
			List<PublicKey> pks = doc.getPublicKeys();
			for (PublicKey pk : pks) {
				DIDURL id = pk.getId();
				String key = storage.loadPrivateKey(id);
				if (key != null) {
					log.debug("Exporting private key {}...", id.toString());
					de.addPrivatekey(id, key, storepass, password);
				}
			}
		}

		return de.seal(password);
	}

	/**
	 * Export the specific DID with all DID objects that related with this DID,
	 * include: document, credentials, private keys and their metadata.
	 *
	 * @param did the DID to be export
	 * @param out the output stream that the data export to
	 * @param password the password to encrypt the private keys in the exported data
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when writing the exported data
	 */
	public void exportDid(DID did, OutputStream out, String password,
			String storepass) throws DIDStoreException, IOException {
		checkArgument(did != null, "Invalid did");
		checkArgument(out != null, "Invalid output stream");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invaid store password");

		exportDid(did, password, storepass).serialize(out, true);
	}

	/**
	 * Export the specific DID with all DID objects that related with this DID,
	 * include: document, credentials, private keys and their metadata.
	 *
	 * @param did the DID to be export
	 * @param out the output stream that the data export to
	 * @param password the password to encrypt the private keys in the exported data
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when writing the exported data
	 */
	public void exportDid(String did, OutputStream out, String password,
			String storepass) throws DIDStoreException, IOException {
		exportDid(DID.valueOf(did), out, password, storepass);
	}

	/**
	 * Export the specific DID with all DID objects that related with this DID,
	 * include: document, credentials, private keys and their metadata.
	 *
	 * @param did the DID to be export
	 * @param out the writer object that the data export to
	 * @param password the password to encrypt the private keys in the exported data
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when writing the exported data
	 */
	public void exportDid(DID did, Writer out, String password,
			String storepass) throws DIDStoreException, IOException {
		checkArgument(did != null, "Invalid did");
		checkArgument(out != null, "Invalid output writer");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invaid store password");

		exportDid(did, password, storepass).serialize(out, true);
	}

	/**
	 * Export the specific DID with all DID objects that related with this DID,
	 * include: document, credentials, private keys and their metadata.
	 *
	 * @param did the DID to be export
	 * @param out the writer object that the data export to
	 * @param password the password to encrypt the private keys in the exported data
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when writing the exported data
	 */
	public void exportDid(String did, Writer out, String password, String storepass)
			throws DIDStoreException, IOException {
		exportDid(DID.valueOf(did), out, password, storepass);
	}

	/**
	 * Export the specific DID with all DID objects that related with this DID,
	 * include: document, credentials, private keys and their metadata.
	 *
	 * @param did the DID to be export
	 * @param file the File object that the data export to
	 * @param password the password to encrypt the private keys in the exported data
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when writing the exported data
	 */
	public void exportDid(DID did, File file, String password, String storepass)
			throws DIDStoreException, IOException {
		checkArgument(did != null, "Invalid did");
		checkArgument(file != null, "Invalid output file");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invaid store password");

		exportDid(did, password, storepass).serialize(file, true);
	}

	/**
	 * Export the specific DID with all DID objects that related with this DID,
	 * include: document, credentials, private keys and their metadata.
	 *
	 * @param did the DID to be export
	 * @param file the File object that the data export to
	 * @param password the password to encrypt the private keys in the exported data
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when writing the exported data
	 */
	public void exportDid(String did, File file, String password, String storepass)
			throws DIDStoreException, IOException {
		exportDid(DID.valueOf(did), file, password, storepass);
	}

	/**
	 * Export the specific DID with all DID objects that related with this DID,
	 * include: document, credentials, private keys and their metadata.
	 *
	 * @param did the DID to be export
	 * @param file the file name that the data export to
	 * @param password the password to encrypt the private keys in the exported data
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when writing the exported data
	 */
	public void exportDid(DID did, String file, String password, String storepass)
			throws DIDStoreException, IOException {
		checkArgument(did != null, "Invalid did");
		checkArgument(file != null && !file.isEmpty(), "Invalid output file name");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invaid store password");

		exportDid(did, new File(file), password, storepass);
	}

	/**
	 * Export the specific DID with all DID objects that related with this DID,
	 * include: document, credentials, private keys and their metadata.
	 *
	 * @param did the DID to be export
	 * @param file the file name that the data export to
	 * @param password the password to encrypt the private keys in the exported data
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when writing the exported data
	 */
	public void exportDid(String did, String file, String password, String storepass)
			throws DIDStoreException, IOException {
		exportDid(DID.valueOf(did), file, password, storepass);
	}

	private void importDid(DIDExport de, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		de.verify(password);

		// Save
		log.debug("Importing document...");
		DIDDocument doc = de.document.content;
		storage.storeDid(doc);
		storage.storeDidMetadata(doc.getSubject(), doc.getMetadata());

		List<VerifiableCredential> vcs =  de.getCredentials();
		for (VerifiableCredential vc : vcs) {
			log.debug("Importing credential {}...", vc.getId().toString());
			storage.storeCredential(vc);
			storage.storeCredentialMetadata(vc.getId(), vc.getMetadata());
		}

		List<DIDExport.PrivateKey> sks = de.getPrivateKeys();
		for (DIDExport.PrivateKey sk : sks) {
			log.debug("Importing private key {}...", sk.getId().toString());
			storage.storePrivateKey(sk.getId(), sk.getKey(password, storepass));
		}
	}

	/**
	 * Import a DID and all related DID object from the exported data to
	 * this store.
	 *
	 * @param in the input stream for the exported data
	 * @param password the password for the exported data
	 * @param storepass the password for this store
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when reading the exported data
	 */
	public void importDid(InputStream in, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		checkArgument(in != null, "Invalid input stream");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invaid store password");

		DIDExport de;
		try {
			de = DIDExport.parse(in, DIDExport.class);
		} catch (DIDSyntaxException e) {
			throw (MalformedExportDataException)e;
		}
		importDid(de, password, storepass);
	}

	/**
	 * Import a DID and all related DID object from the exported data to
	 * this store.
	 *
	 * @param in the reader object for the exported data
	 * @param password the password for the exported data
	 * @param storepass the password for this store
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when reading the exported data
	 */
	public void importDid(Reader in, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		checkArgument(in != null, "Invalid input reader");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invaid store password");

		DIDExport de;
		try {
			de = DIDExport.parse(in, DIDExport.class);
		} catch (DIDSyntaxException e) {
			throw (MalformedExportDataException)e;
		}
		importDid(de, password, storepass);
	}

	/**
	 * Import a DID and all related DID object from the exported data to
	 * this store.
	 *
	 * @param file the file object for the exported data
	 * @param password the password for the exported data
	 * @param storepass the password for this store
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when reading the exported data
	 */
	public void importDid(File file, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		checkArgument(file != null, "Invalid input file");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invaid store password");

		DIDExport de;
		try {
			de = DIDExport.parse(file, DIDExport.class);
		} catch (DIDSyntaxException e) {
			throw (MalformedExportDataException)e;
		}
		importDid(de, password, storepass);
	}

	/**
	 * Import a DID and all related DID object from the exported data to
	 * this store.
	 *
	 * @param file the file name for the exported data
	 * @param password the password for the exported data
	 * @param storepass the password for this store
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when reading the exported data
	 */
	public void importDid(String file, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		checkArgument(file != null, "Invalid input file name");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invaid store password");

		importDid(new File(file), password, storepass);
	}

	@JsonPropertyOrder({ "type", "mnemonic", "privateKey", "publicKey",
						 "index", "default",  "created", "fingerprint" })
	@JsonInclude(Include.NON_NULL)
	static class RootIdentityExport extends DIDEntity<RootIdentityExport> {
		@JsonProperty("type")
		private String type;
		@JsonProperty("mnemonic")
		private String mnemonic;
		@JsonProperty("privateKey")
		private String privateKey;
		@JsonProperty("publicKey")
		private String publicKey;
		@JsonProperty("index")
		private int index;
		@JsonProperty("default")
		@JsonInclude(Include.NON_NULL)
		private Boolean isDefault;
		@JsonProperty("created")
		private Date created;
		@JsonProperty("fingerprint")
		private String fingerprint;

		@JsonCreator
		protected RootIdentityExport(@JsonProperty(value = "type", required = true) String type) {
			if (type == null)
				throw new IllegalArgumentException("Invalid export type");

			this.type = type;
		}

		public String getMnemonic(String exportpass, String storepass)
				throws DIDStoreException {
			return mnemonic == null ? null : reEncrypt(mnemonic, exportpass, storepass);
		}

		public void setMnemonic(String mnemonic, String storepass, String exportpass)
				throws DIDStoreException {
			this.mnemonic = reEncrypt(mnemonic, storepass, exportpass);
		}

		public String getPrivateKey(String exportpass, String storepass)
				throws DIDStoreException {
			return reEncrypt(privateKey, exportpass, storepass);
		}

		public void setPrivateKey(String privateKey, String storepass, String exportpass)
				throws DIDStoreException {
			this.privateKey = reEncrypt(privateKey, storepass, exportpass);
		}

		public String getPublicKey() {
			return publicKey;
		}

		public void setPubkey(String publicKey) {
			this.publicKey = publicKey;
		}

		public int getIndex() {
			return index;
		}

		public void setIndex(int index) {
			this.index = index;
		}

		public boolean isDefault() {
			return isDefault == null ? false : isDefault;
		}

		public void setDefault() {
			isDefault = Boolean.valueOf(true);
		}

		private String calculateFingerprint(String exportpass) {
			SHA256Digest sha256 = new SHA256Digest();
			byte[] bytes = exportpass.getBytes();
			sha256.update(bytes, 0, bytes.length);

			bytes = type.getBytes();
			sha256.update(bytes, 0, bytes.length);

			if (mnemonic != null) {
				bytes = mnemonic.getBytes();
				sha256.update(bytes, 0, bytes.length);
			}

			bytes = privateKey.getBytes();
			sha256.update(bytes, 0, bytes.length);

			bytes = publicKey.getBytes();
			sha256.update(bytes, 0, bytes.length);

			bytes = Integer.toString(index).getBytes();
			sha256.update(bytes, 0, bytes.length);

			bytes = Boolean.toString(isDefault()).getBytes();
			sha256.update(bytes, 0, bytes.length);

			bytes = dateFormat.format(created).getBytes();
			sha256.update(bytes, 0, bytes.length);

			byte digest[] = new byte[32];
			sha256.doFinal(digest, 0);
			return Base64.encodeToString(digest,
					Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
		}

		public RootIdentityExport seal(String exportpass) {
			Calendar now = Calendar.getInstance();
			now.set(Calendar.MILLISECOND, 0);
			this.created = now.getTime();
			this.fingerprint = calculateFingerprint(exportpass);
			return this;
		}

		public void verify(String exportpass) throws MalformedExportDataException {
			if (!fingerprint.equals(calculateFingerprint(exportpass)))
				throw new MalformedExportDataException(
							"Invalid export data, fingerprint mismatch.");
		}

		@Override
		protected void sanitize() throws MalformedExportDataException {
			if (type == null || !type.equals(DID_EXPORT))
				throw new MalformedExportDataException(
						"Invalid export data, unknown type.");

			if (created == null)
				throw new MalformedExportDataException(
						"Invalid export data, missing created time.");

			if (privateKey == null || privateKey.isEmpty())
				throw new MalformedExportDataException(
						"Invalid export data, missing key.");

			if (fingerprint == null || fingerprint.isEmpty())
				throw new MalformedExportDataException(
						"Invalid export data, missing fingerprint.");
		}
	}

	private RootIdentityExport exportRootIdentity(String id,
			String password, String storepass)
			throws DIDStoreException {
		RootIdentityExport rie = new RootIdentityExport(DID_EXPORT);

		// TODO: support multiple named root identities
		String mnemonic = storage.loadRootIdentityMnemonic(id);
		if (mnemonic != null)
			rie.setMnemonic(mnemonic, storepass, password);

		rie.setPrivateKey(storage.loadRootIdentityPrivateKey(id), storepass, password);

		RootIdentity identity = storage.loadRootIdentity(id);
		rie.setPubkey(identity.getPreDerivedPublicKey().serializePublicKeyBase58());
		rie.setIndex(identity.getIndex());

		if (identity.getId().equals(metadata.getDefaultRootIdentity()))
			rie.setDefault();

		return rie.seal(password);
	}

	/**
	 * Export the specific RootIdentity, include: mnemonic, private key,
	 * pre-derived public key, derive index, metadata...
	 *
	 * @param id the id of the RootIdentity to be export
	 * @param out the output stream that the data export to
	 * @param password the password to encrypt the private keys in the exported data
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when writing the exported data
	 */
	public void exportRootIdentity(String id, OutputStream out,
			String password, String storepass)
			throws DIDStoreException, IOException {
		checkArgument(id != null && !id.isEmpty(), "Invalid identity id");
		checkArgument(out != null, "Invalid output stream");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		exportRootIdentity(id, password, storepass).serialize(out);
	}

	/**
	 * Export the specific RootIdentity, include: mnemonic, private key,
	 * pre-derived public key, derive index, metadata...
	 *
	 * @param id the id of the RootIdentity to be export
	 * @param out the writer object that the data export to
	 * @param password the password to encrypt the private keys in the exported data
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when writing the exported data
	 */
	public void exportRootIdentity(String id, Writer out,
			String password, String storepass)
			throws DIDStoreException, IOException {
		checkArgument(id != null && !id.isEmpty(), "Invalid identity id");
		checkArgument(out != null, "Invalid output writer");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		exportRootIdentity(id, password, storepass).serialize(out);
	}

	/**
	 * Export the specific RootIdentity, include: mnemonic, private key,
	 * pre-derived public key, derive index, metadata...
	 *
	 * @param id the id of the RootIdentity to be export
	 * @param file the file object that the data export to
	 * @param password the password to encrypt the private keys in the exported data
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when writing the exported data
	 */
	public void exportRootIdentity(String id, File file,
			String password, String storepass)
			throws DIDStoreException, IOException {
		checkArgument(id != null && !id.isEmpty(), "Invalid identity id");
		checkArgument(file != null, "Invalid output file");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		exportRootIdentity(id, password, storepass).serialize(file);
	}

	/**
	 * Export the specific RootIdentity, include: mnemonic, private key,
	 * pre-derived public key, derive index, metadata...
	 *
	 * @param id the id of the RootIdentity to be export
	 * @param file the file name that the data export to
	 * @param password the password to encrypt the private keys in the exported data
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when writing the exported data
	 */
	public void exportRootIdentity(String id, String file,
			String password, String storepass)
			throws DIDStoreException, IOException {
		checkArgument(id != null && !id.isEmpty(), "Invalid identity id");
		checkArgument(file != null && !file.isEmpty(), "Invalid output file name");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		exportRootIdentity(id, new File(file), password, storepass);
	}

	private void importRootIdentity(RootIdentityExport rie, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		rie.verify(password);

		// Save
		String encryptedMnemonic = rie.getMnemonic(password, storepass);
		String encryptedPrivateKey = (rie.getPrivateKey(password, storepass));
		String publicKey = rie.getPublicKey();
		HDKey pk = HDKey.deserializeBase58(publicKey);
		String id = RootIdentity.getId(pk.serializePublicKey());

		storage.storeRootIdentity(id, encryptedMnemonic, encryptedPrivateKey,
				publicKey, rie.getIndex());

		if (rie.isDefault() && metadata.getDefaultRootIdentity() == null)
			metadata.setDefaultRootIdentity(id);
	}

	/**
	 * Import a RootIdentity object from the exported data to this store.
	 *
	 * @param in the input stream for the exported data
	 * @param password the password for the exported data
	 * @param storepass the password for this store
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when reading the exported data
	 */
	public void importRootIdentity(InputStream in, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException  {
		checkArgument(in != null, "Invalid input stream");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		try {
			RootIdentityExport rie = RootIdentityExport.parse(in, RootIdentityExport.class);
			importRootIdentity(rie, password, storepass);
		} catch (DIDSyntaxException e) {
			throw (MalformedExportDataException)e;
		}
	}

	/**
	 * Import a RootIdentity object from the exported data to this store.
	 *
	 * @param in the reader object for the exported data
	 * @param password the password for the exported data
	 * @param storepass the password for this store
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when reading the exported data
	 */
	public void importRootIdentity(Reader in, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		checkArgument(in != null, "Invalid input reader");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		try {
			RootIdentityExport rie = RootIdentityExport.parse(in, RootIdentityExport.class);
			importRootIdentity(rie, password, storepass);
		} catch (DIDSyntaxException e) {
			throw (MalformedExportDataException)e;
		}
	}

	/**
	 * Import a RootIdentity object from the exported data to this store.
	 *
	 * @param file the file object for the exported data
	 * @param password the password for the exported data
	 * @param storepass the password for this store
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when reading the exported data
	 */
	public void importRootIdentity(File file, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		checkArgument(file != null, "Invalid input file");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		try {
			RootIdentityExport rie = RootIdentityExport.parse(file, RootIdentityExport.class);
			importRootIdentity(rie, password, storepass);
		} catch (DIDSyntaxException e) {
			throw (MalformedExportDataException)e;
		}
	}

	/**
	 * Import a RootIdentity object from the exported data to this store.
	 *
	 * @param file the file name for the exported data
	 * @param password the password for the exported data
	 * @param storepass the password for this store
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when reading the exported data
	 */
	public void importRootIdentity(String file, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		checkArgument(file != null && !file.isEmpty(), "Invalid input file name");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		importRootIdentity(new File(file), password, storepass);
	}

	/**
	 * Export all DID objects from this store.
	 *
	 * @param out the zip output stream that the data export to
	 * @param password the password to encrypt the private keys in the exported data
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when writing the exported data
	 */
	public void exportStore(ZipOutputStream out, String password,
			String storepass) throws DIDStoreException, IOException {
		checkArgument(out != null, "Invalid zip output stream");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		ZipEntry ze;

		List<RootIdentity> ris = listRootIdentities();
		for (RootIdentity ri : ris) {
			ze = new ZipEntry("rootIdentity-" + ri.getId());
			out.putNextEntry(ze);
			exportRootIdentity(ri.getId(), out, password, storepass);
			out.closeEntry();
		}

		List<DID> dids = listDids();
		for (DID did : dids) {
			ze = new ZipEntry(did.getMethodSpecificId());
			out.putNextEntry(ze);
			exportDid(did, out, password, storepass);
			out.closeEntry();
		}
	}

	/**
	 * Export all DID objects from this store.
	 *
	 * @param zipFile the ZipFile object that the data export to
	 * @param password the password to encrypt the private keys in the exported data
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when writing the exported data
	 */
	public void exportStore(File zipFile, String password, String storepass)
			throws DIDStoreException, IOException {
		checkArgument(zipFile != null, "Invalid zip output file");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		ZipOutputStream out = new ZipOutputStream(new FileOutputStream(zipFile));
		exportStore(out, password, storepass);
		out.close();
	}

	/**
	 * Export all DID objects from this store.
	 *
	 * @param zipFile the zip file name that the data export to
	 * @param password the password to encrypt the private keys in the exported data
	 * @param storepass the password for this store
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when writing the exported data
	 */
	public void exportStore(String zipFile, String password, String storepass)
			throws DIDStoreException, IOException {
		checkArgument(zipFile != null && !zipFile.isEmpty(), "Invalid zip output file name");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		exportStore(new File(zipFile), password, storepass);
	}

	/**
	 * Import a exported DIDStore from the exported data to this store.
	 *
	 * @param in the zip input stream for the exported data
	 * @param password the password for the exported data
	 * @param storepass the password for this store
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when reading the exported data
	 */
	public void importStore(ZipInputStream in, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		checkArgument(in != null, "Invalid zip input stream");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		String fingerprint = metadata.getFingerprint();
		String currentFingerprint = calcFingerprint(storepass);

		if (fingerprint != null && !currentFingerprint.equals(fingerprint))
			throw new WrongPasswordException("Password mismatched with previous password.");

		ZipEntry ze;
		while ((ze = in.getNextEntry()) != null) {
			if (ze.getName().startsWith("rootIdentity"))
				importRootIdentity(in, password, storepass);
			else
				importDid(in, password, storepass);
			in.closeEntry();
		}

		if (fingerprint == null || fingerprint.isEmpty())
			metadata.setFingerprint(currentFingerprint);
	}

	/**
	 * Import a exported DIDStore from the exported data to this store.
	 *
	 * @param zipFile the ZipFile object for the exported data
	 * @param password the password for the exported data
	 * @param storepass the password for this store
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when reading the exported data
	 */
	public void importStore(File zipFile, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		checkArgument(zipFile != null, "Invalid zip input file");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		ZipInputStream in = new ZipInputStream(new FileInputStream(zipFile));
		importStore(in, password, storepass);
		in.close();
	}

	/**
	 * Import a exported DIDStore from the exported data to this store.
	 *
	 * @param zipFile the zip file name for the exported data
	 * @param password the password for the exported data
	 * @param storepass the password for this store
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException if an error occurred when accessing the store
	 * @throws IOException if an IO error occurred when reading the exported data
	 */
	public void importStore(String zipFile, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		checkArgument(zipFile != null && !zipFile.isEmpty(), "Invalid zip input file name");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		importStore(new File(zipFile), password, storepass);
	}
}
