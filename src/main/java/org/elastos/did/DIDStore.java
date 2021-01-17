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
import java.util.concurrent.ExecutionException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.elastos.did.DIDDocument.PublicKey;
import org.elastos.did.crypto.Aes256cbc;
import org.elastos.did.crypto.Base64;
import org.elastos.did.crypto.EcdsaSigner;
import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.DIDStorageException;
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
 * DIDStore is local store for all DIDs.
 */
public final class DIDStore {
	protected static final String DID_STORE_TYPE = "did:elastos:store";
	protected static final int DID_STORE_VERSION = 3;

	private static final int CACHE_INITIAL_CAPACITY = 16;
	private static final int CACHE_MAX_CAPACITY = 128;

	private static final Object NULL = new Object();

	private static final String DID_EXPORT = "did.elastos.export/1.0";

	private Cache<Object, Object> cache;

	private DIDStorage storage;
	private Metadata metadata;

	private static final Logger log = LoggerFactory.getLogger(DIDStore.class);

	static class Metadata extends AbstractMetadata {
		private static final String TYPE = "type";
		private static final String VERSION = "version";
		private static final String FINGERPRINT = "fingerprint";
		private static final String DEFAULT_ROOT_IDENTITY = "defaultRootIdentity";

		protected Metadata(DIDStore store) {
			super();
			put(TYPE, DID_STORE_TYPE);
			put(VERSION, DID_STORE_VERSION);
			if (store != null)
				attachStore(store);
		}

		protected Metadata() {
			this(null);
		}

		protected String getType() {
			return get(TYPE);
		}

		public int getVersion() {
			return getInteger(VERSION);
		}

		public void setFingerprint(String fingerprint) {
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
	 * The interface for ConflictHandle to indicate how to resolve the conflict,
	 * if the local document is different with the one resolved from chain.
	 */
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

	public interface DIDFilter {
		public boolean select(DID did);
	}

	public interface CredentialFilter {
		public boolean select(DIDURL id);
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
	}

	/**
	 * Initialize or check the DIDStore.
	 *
	 * @param type the type for different file system
	 * @param location the location of DIDStore
	 * @param initialCacheCapacity the initial capacity for cache
	 * @param maxCacheCapacity the max capacity for cache
	 * @return the DIDStore object
	 * @throws DIDStoreException Unsupport the specified store type.
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

	public static DIDStore open(String location,
			int initialCacheCapacity, int maxCacheCapacity) throws DIDStoreException {
		checkArgument(location != null && !location.isEmpty(), "Invalid store location");

		return open(new File(location), initialCacheCapacity, maxCacheCapacity);
	}

	public static DIDStore open(File location)
			throws DIDStoreException {
		return open(location, CACHE_INITIAL_CAPACITY, CACHE_MAX_CAPACITY);
	}

	/**
	 * Initialize or check the DIDStore.
	 *
	 * @param type the type for different file system
	 * @param location the location of DIDStore
	 * @return the DIDStore object
	 * @throws DIDStoreException Unsupport the specified store type.
	 */
	public static DIDStore open(String location)
			throws DIDStoreException {
		return open(location, CACHE_INITIAL_CAPACITY, CACHE_MAX_CAPACITY);
	}

	public void close() {
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
			throw new DIDStoreException("Calculate fingerprint error.", e);
		}
	}

	/**
	 * Encrypt by Base64 method.
	 *
	 * @param input the data be encrypted
	 * @param passwd the password for encrypting
	 * @return the encrypt result
	 * @throws DIDStoreException Encrypt data error.
	 */
	protected static String encryptToBase64(byte[] input, String passwd)
			throws DIDStoreException {
		try {
			byte[] cipher = Aes256cbc.encrypt(input, passwd);

			return Base64.encodeToString(cipher,
					Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
		} catch (CryptoException e) {
			throw new DIDStoreException("Encrypt data error.", e);
		}
	}

	/**
	 * Decrypt data from Base64 method.
	 *
	 * @param input the data to decrypted
	 * @param passwd the password for decrypting
	 * @return the original data before encrpting
	 * @throws DIDStoreException Decrypt private key error.
	 */
	protected static byte[] decryptFromBase64(String input, String passwd)
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
	}

	protected void storeRootIdentity(RootIdentity identity)
			throws DIDStoreException {
		checkArgument(identity != null, "Invalid identity");
		storage.updateRootIdentityIndex(identity.getId(), identity.getIndex());
	}

    /**
     * Load private identity from DIDStore.
     *
     * @param storepass the password for DIDStore
     * @return the HDKey object(private identity)
     * @throws DIDStoreException there is invalid private identity in DIDStore.
     */
	public RootIdentity loadRootIdentity(String id)
			throws DIDStoreException {
		checkArgument(id != null && !id.isEmpty(), "Invalid id");

		String key = "root-identity:" + id;

		try {
			Object value = cache.get(key, new Callable<Object>() {
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

	public RootIdentity loadRootIdentity() throws DIDStoreException {
		String id = metadata.getDefaultRootIdentity();
		if (id == null || id.isEmpty())
			return null;

		return loadRootIdentity(id);
	}

	/**
	 * Judge whether private identity exists in DIDStore.
	 *
	 * @return the returned value is true if private identity exists;
	 *         the returned value if false if private identity doesnot exist.
	 * @throws DIDStoreException Unsupport the specified store type.
	 */
	public boolean containsRootIdentity(String id) throws DIDStoreException {
		return storage.loadRootIdentity(id) != null;
	}

	/**
	 * Export mnemonic from DIDStore
	 *
	 * @param storepass the password for DIDStore
 	 * @return the mnemonic string
	 * @throws DIDStoreException there is no mnemonic in DID Store.
	 */
	public String exportRootIdentityMnemonic(String id, String storepass) throws DIDStoreException {
		checkArgument(id != null && !id.isEmpty(), "Invalid id");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		String encryptedMnemonic = storage.loadRootIdentityMnemonic(id);
		if (encryptedMnemonic != null)
			return new String(decrypt(encryptedMnemonic, storepass));
		else
			return null;
	}

	public boolean containsRootIdentityMnemonic(String id) throws DIDStoreException {
		checkArgument(id != null && !id.isEmpty(), "Invalid id");

		String encryptedMnemonic = storage.loadRootIdentityMnemonic(id);
		return encryptedMnemonic != null;
	}

    /**
     * Load private identity from DIDStore.
     *
     * @param storepass the password for DIDStore
     * @return the HDKey object(private identity)
     * @throws DIDStoreException there is invalid private identity in DIDStore.
     */
	private HDKey loadRootIdentityPrivateKey(String id, String storepass)
			throws DIDStoreException {
		String key = "root-identity:" + id + "#privatekey";

		try {
			Object value = cache.get(key, new Callable<Object>() {
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

	protected HDKey derive(String id, String path, String storepass)
			throws DIDStoreException {
		checkArgument(id != null && !id.isEmpty(), "Invalid identity");
		checkArgument(path != null && !path.isEmpty(), "Invalid path");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		HDKey rootPrivateKey = loadRootIdentityPrivateKey(id, storepass);
		HDKey key = rootPrivateKey.derive(path);
		rootPrivateKey.wipe();

		return key;
	}

	public boolean deleteRootIdentity(String id) throws DIDStoreException {
		checkArgument(id != null && !id.isEmpty(), "Invalid id");

		boolean success = storage.deleteRootIdentity(id);
		if (success && metadata.getDefaultRootIdentity() != null &&
				metadata.getDefaultRootIdentity().equals(id))
			metadata.setDefaultRootIdentity(null);

		return success;
	}

	public List<RootIdentity> listRootIdentities() throws DIDStoreException {
		return storage.listRootIdentities();
	}

	public boolean containsRootIdentities() throws DIDStoreException {
		return storage.containsRootIdenities();
	}

	protected void storeRootIdentityMetadata(String id, RootIdentity.Metadata metadata)
			throws DIDStoreException {
		checkArgument(id != null && !id.isEmpty(), "Invalid id");
		checkArgument(metadata != null, "Invalid metadata");

		storage.storeRootIdentityMetadata(id, metadata);
	}

	protected RootIdentity.Metadata loadRootIdentityMetadata(String id)
			throws DIDStoreException {
		checkArgument(id != null && !id.isEmpty(), "Invalid id");

		RootIdentity.Metadata metadata = storage.loadRootIdentityMetadata(id);
		if (metadata != null)
			metadata.attachStore(this);
		else
			metadata = new RootIdentity.Metadata(id, this);

		return metadata;
	}

    /**
     * Store DID Document in the DIDStore.
     *
     * @param doc the DIDDocument object
     * @throws DIDStoreException DIDStore error.
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

		cache.put(doc.getSubject(), doc);
	}

	/**
	 * Load the specified DID content(DIDDocument).
	 *
	 * @param did the specified DID
	 * @return the DIDDocument object
	 * @throws DIDStoreException DIDStore error.
	 */
	public DIDDocument loadDid(DID did) throws DIDStoreException {
		checkArgument(did != null, "Invalid did");

		try {
			Object value = cache.get(did, new Callable<Object>() {
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
	 * Load the specified DID content(DIDDocument).
	 *
	 * @param did the specified DID string
	 * @return the DIDDocument object
	 * @throws DIDStoreException DIDStore error.
	 */
	public DIDDocument loadDid(String did) throws DIDStoreException {
		return loadDid(DID.valueOf(did));
	}

    /**
     * Judge whether containing the specified DID or not.
     *
     * @param did the specified DID
     * @return the returned value is true if the specified DID is in the DIDStore;
     *         the returned value is false if the specified DID is not in the DIDStore.
     * @throws DIDStoreException DIDStore error.
     */
	public boolean containsDid(DID did) throws DIDStoreException {
		checkArgument(did != null, "Invalid did");
		return loadDid(did) != null;
	}

    /**
     * Judge whether containing the specified DID or not.
     *
     * @param did the specified DID string
     * @return the returned value is true if the specified DID is in the DIDStore;
     *         the returned value is false if the specified DID is not in the DIDStore.
     * @throws DIDStoreException DIDStore error.
     */
	public boolean containsDid(String did) throws DIDStoreException {
		return containsDid(DID.valueOf(did));
	}

	/**
	 * Store DID Metadata.
	 *
	 * @param did the owner of Metadata
	 * @param metadata the meta data
	 * @throws DIDStoreException DIDStore error.
	 */
	protected void storeDidMetadata(DID did, DIDMetadata metadata)
			throws DIDStoreException {
		checkArgument(did != null, "Invalid did");
		checkArgument(metadata != null, "Invalid metadata");

		storage.storeDidMetadata(did, metadata);
		metadata.attachStore(this);

		DIDURL id = new DIDURL(did, ";metadata");
		cache.put(id, metadata);
	}

	/**
	 * Load Meta data for the specified DID.
	 *
	 * @param did the specified DID
	 * @return the Meta data
	 * @throws DIDStoreException DIDStore error.
	 */
	protected DIDMetadata loadDidMetadata(DID did) throws DIDStoreException {
		checkArgument(did != null, "Invalid did");

		DIDURL id = new DIDURL(did, ";metadata");
		try {
			Object value = cache.get(id , new Callable<Object>() {
			    @Override
			    public Object call() throws DIDStorageException {
					DIDMetadata metadata = storage.loadDidMetadata(did);
					if (metadata != null)
						metadata.attachStore(DIDStore.this);
					else
						metadata = new DIDMetadata(did, DIDStore.this);

					return metadata;
			    }
			});

			return value == NULL ? null : (DIDMetadata)value;
		} catch (ExecutionException e) {
			throw new DIDStoreException("Load did metadata failed: " + did, e);
		}
	}


    /**
     * Delete the specified DID.
     *
     * @param did the specified DID
     * @return the returned value is true if deleting is successful;
     *         the returned value is false if deleting is failed.
     * @throws DIDStoreException DIDStore error.
     */
	public boolean deleteDid(DID did) throws DIDStoreException {
		checkArgument(did != null, "Invalid did");

		cache.invalidate(did);
		return storage.deleteDid(did);
	}

    /**
     * Delete the specified DID.
     *
     * @param did the specified DID string
     * @return the returned value is true if deleting is successful;
     *         the returned value is false if deleting is failed.
     * @throws DIDStoreException DIDStore error.
     */
	public boolean deleteDid(String did) throws DIDStoreException {
		return deleteDid(DID.valueOf(did));
	}

	/**
	 * List all DIDs according to the specified condition.
	 *
	 * @return the DID array.
	 * @throws DIDStoreException DIDStore error.
	 */
	public List<DID> listDids() throws DIDStoreException {
		List<DID> dids = storage.listDids();
		for (DID did : dids) {
			DIDMetadata metadata = loadDidMetadata(did);
			did.setMetadata(metadata);
		}

		return dids;
	}

	public List<DID> selectDids(DIDFilter filter) throws DIDStoreException {
		List<DID> src = listDids();

		if (filter != null) {
			List<DID> dest = new ArrayList<DID>();

			for (DID did : src) {
				if (filter.select(did))
					dest.add(did);
			}

			return dest;
		} else {
			return src;
		}
	}

	/**
	 * Store the specified Credential.
	 *
	 * @param credential the Credential object
	 * @throws DIDStoreException DIDStore error.
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

		cache.put(credential.getId(), credential);
	}

	/**
	 * Load the specified Credential.
	 *
	 * @param did the owner of Credential
	 * @param id the identifier of Credential
	 * @return the Credential object
	 * @throws DIDStoreException DIDStore error.
	 */
	public VerifiableCredential loadCredential(DIDURL id)
			throws DIDStoreException {
		checkArgument(id != null, "Invalid id");

		try {
			Object value = cache.get(id, new Callable<Object>() {
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
	 * Load the specified Credential.
	 *
	 * @param did the owner of Credential
	 * @param id the identifier of Credential
	 * @return the Credential object
	 * @throws DIDStoreException DIDStore error.
	 */
	public VerifiableCredential loadCredential(String id)
			throws DIDStoreException {
		return loadCredential(DIDURL.valueOf(id));
	}

	/**
	 * Judge whether does DIDStore contain the specified credential.
	 *
	 * @param did the owner of Credential
	 * @param id the identifier of Credential
	 * @return the returned value is true if there is no credential owned the specific DID;
	 *         the returned value is false if there is credentials owned the specific DID.
	 * @throws DIDStoreException DIDStore error.
	 */
	public boolean containsCredential(DIDURL id)
			throws DIDStoreException {
		checkArgument(id != null, "Invalid id");
		return loadCredential(id) != null;
	}

	/**
	 * Judge whether does DIDStore contain the specified credential.
	 *
	 * @param did the owner of Credential
	 * @param id the identifier of Credential
	 * @return the returned value is true if there is no credential owned the specific DID;
	 *         the returned value is false if there is credentials owned the specific DID.
	 * @throws DIDStoreException DIDStore error.
	 */
	public boolean containsCredential(String id)
			throws DIDStoreException {
		return containsCredential(DIDURL.valueOf(id));
	}

	/**
	 * Judge whether does DIDStore contain any credential owned the specific DID.
	 *
	 * @param did the owner of Credential
	 * @return the returned value is true if there is no credential owned the specific DID.
	 * @throws DIDStoreException DIDStore error.
	 */
	public boolean containsCredentials(DID did) throws DIDStoreException {
		checkArgument(did != null, "Invalid did");
		return storage.containsCredentials(did);
	}

	/**
	 * Judge whether does DIDStore contain any credential owned the specific DID.
	 *
	 * @param did the owner of Credential
	 * @return the returned value is true if there is no credential owned the specific DID.
	 * @throws DIDStoreException DIDStore error.
	 */
	public boolean containsCredentials(String did) throws DIDStoreException {
		return containsCredentials(DID.valueOf(did));
	}

    /**
     * Store meta data for the specified Credential.
     *
     * @param did the owner of the specified Credential
     * @param id the identifier of Credential
     * @param metadata the meta data for Credential
     * @throws DIDStoreException DIDStore error.
     */
	protected void storeCredentialMetadata(DIDURL id,
			CredentialMetadata metadata) throws DIDStoreException {
		checkArgument(id != null, "Invalid id");
		checkArgument(metadata != null, "Invalid metadata");

		storage.storeCredentialMetadata(id, metadata);
		metadata.attachStore(this);

		DIDURL.Builder builder = new DIDURL.Builder(id);
		builder.setParameter("metadata", null);
		DIDURL metadataId = builder.build();
		cache.put(metadataId, metadata);
	}

	/**
	 * Load the meta data about the specified Credential.
	 *
	 * @param did the owner of Credential
     * @param id the identifier of Credential
	 * @return the meta data for Credential
	 * @throws DIDStoreException DIDStore error.
	 */
	protected CredentialMetadata loadCredentialMetadata(DIDURL id)
			throws DIDStoreException {
		checkArgument(id != null, "Invalid id");

		DIDURL.Builder builder = new DIDURL.Builder(id);
		builder.setParameter("metadata", null);
		DIDURL metadataId = builder.build();

		try {
			Object value = cache.get(metadataId , new Callable<Object>() {
			    @Override
			    public Object call() throws DIDStorageException {
					CredentialMetadata metadata = storage.loadCredentialMetadata(id);
					if (metadata != null)
						metadata.attachStore(DIDStore.this);
					else
						metadata = new CredentialMetadata(id, DIDStore.this);

					return metadata;
			    }
			});

			return value == NULL ? null : (CredentialMetadata)value;
		} catch (ExecutionException e) {
			throw new DIDStoreException("Load Credential metadata failed: " + id, e);
		}
	}

	/**
	 * Delete the specified Credential
	 *
	 * @param did the owner of Credential
	 * @param id the identifier of Credential
	 * @return the returned value is true if there is no credential owned the specific DID;
	 *         the returned value is false if there is credentials owned the specific DID.
	 * @throws DIDStoreException DIDStore error.
	 */
	public boolean deleteCredential(DIDURL id) throws DIDStoreException {
		checkArgument(id != null, "Invalid id");
		cache.invalidate(id);
		return storage.deleteCredential(id);
	}

	/**
	 * Delete the specified Credential
	 *
	 * @param did the owner of Credential
	 * @param id the identifier of Credential
	 * @return the returned value is true if there is no credential owned the specific DID;
	 *         the returned value is false if there is credentials owned the specific DID.
	 * @throws DIDStoreException DIDStore error.
	 */
	public boolean deleteCredential(String id)
			throws DIDStoreException {
		return deleteCredential(DIDURL.valueOf(id));
	}

	/**
	 * List the Credentials owned the specified DID.
	 *
	 * @param did the owner of Credential
	 * @return the Credential array owned the specified DID.
	 * @throws DIDStoreException DIDStore error.
	 */
	public List<DIDURL> listCredentials(DID did) throws DIDStoreException {
		checkArgument(did != null, "Invalid did");

		List<DIDURL> ids = storage.listCredentials(did);
		for (DIDURL id : ids) {
			CredentialMetadata metadata = loadCredentialMetadata(id);
			id.setMetadata(metadata);
		}

		return ids;
	}

	/**
	 * List the Credentials owned the specified DID.
	 *
	 * @param did the owner of Credential
	 * @return the Credential array owned the specified DID.
	 * @throws DIDStoreException DIDStore error.
	 */
	public List<DIDURL> listCredentials(String did) throws DIDStoreException {
		return listCredentials(DID.valueOf(did));
	}

	/**
	 * Select the Credentials according to the specified condition.
	 *
	 * @param did the owner of Credential
	 * @param id the identifier of Credential
	 * @param type the Credential type
	 * @return the Credential array
	 * @throws DIDStoreException DIDStore error.
	 */
	public List<DIDURL> selectCredentials(DID did, CredentialFilter filter)
			throws DIDStoreException {
		checkArgument(did != null, "Invalid did");

		List<DIDURL> src = listCredentials(did);

		if (filter != null) {
			List<DIDURL> dest = new ArrayList<DIDURL>();

			for (DIDURL id : src) {
				if (filter.select(id))
					dest.add(id);
			}

			return dest;
		} else {
			return src;
		}
	}

	/**
	 * Select the Credentials according to the specified condition.
	 *
	 * @param did the owner of Credential
	 * @param id the identifier of Credential
	 * @param type the Credential type
	 * @return the Credential array
	 * @throws DIDStoreException DIDStore error.
	 */
	public List<DIDURL> selectCredentials(String did, CredentialFilter filter)
			throws DIDStoreException {
		return selectCredentials(DID.valueOf(did), filter);
	}

	/**
	 * Store private key. Encrypt and encode private key with base64url method.
	 *
	 * @param did the owner of key
	 * @param id the identifier of key
	 * @param privateKey the original private key(32 bytes)
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error.
	 */
	public void storePrivateKey(DIDURL id, byte[] privateKey,
			String storepass) throws DIDStoreException {
		checkArgument(id != null, "Invalid id");
		checkArgument(privateKey != null && privateKey.length != 0, "Invalid private key");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		String encryptedKey = encrypt(privateKey, storepass);
		storage.storePrivateKey(id, encryptedKey);

		cache.put(id, encryptedKey);
	}

	/**
	 * Store private key. Encrypt and encode private key with base64url method.
	 *
	 * @param did the owner of key
	 * @param id the identifier of key
	 * @param privateKey the original private key(32 bytes)
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error.
	 */
	public void storePrivateKey(String id, byte[] privateKey,
			String storepass) throws DIDStoreException {
		storePrivateKey(DIDURL.valueOf(id), privateKey, storepass);
	}

	private String loadPrivateKey(DIDURL id) throws DIDStoreException {
		try {
			Object value = cache.get(id, new Callable<Object>() {
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

	/**
	 * Load private key.
	 *
	 * @param did the owner of key
	 * @param id the identifier of key
	 * @param storepass the password for DIDStore
	 * @return the original private key
	 * @throws DIDStoreException DIDStore error.
	 */
	protected byte[] loadPrivateKey(DIDURL id, String storepass)
			throws DIDStoreException {
		checkArgument(id != null, "Invalid id");
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
	 * Judge that the specified key has private key in DIDStore.
	 *
	 * @param did the owner of key
	 * @param id the identifier of key
	 * @return the returned value is true if there is private keys owned the specified key;
	 *         the returned value is false if there is no private keys owned the specified key.
	 * @throws DIDStoreException DIDStore error.
	 */
	public boolean containsPrivateKey(DIDURL id) throws DIDStoreException {
		checkArgument(id != null, "Invalid id");
		return loadPrivateKey(id) != null;
	}

	/**
	 * Judge that the specified key has private key in DIDStore.
	 *
	 * @param did the owner of key
	 * @param id the identifier of key
	 * @return the returned value is true if there is private keys owned the specified key;
	 *         the returned value is false if there is no private keys owned the specified key.
	 * @throws DIDStoreException DIDStore error.
	 */
	public boolean containsPrivateKey(String id) throws DIDStoreException {
		return containsPrivateKey(DIDURL.valueOf(id));
	}

	/**
	 * Judge whether there is private key owned the specified DID in DIDStore.
	 *
	 * @param did the specified DID
	 * @return the returned value is true if there is private keys owned the specified DID;
	 *         the returned value is false if there is no private keys owned the specified DID.
	 * @throws DIDStoreException DIDStore error.
	 */
	public boolean containsPrivateKeys(DID did) throws DIDStoreException {
		checkArgument(did != null, "Invalid did");
		return storage.containsPrivateKeys(did);
	}

	/**
	 * Judge whether there is private key owned the specified DID in DIDStore.
	 *
	 * @param did the specified DID string
	 * @return the returned value is true if there is private keys owned the specified DID;
	 *         the returned value is false if there is no private keys owned the specified DID.
	 * @throws DIDStoreException DIDStore error.
	 */
	public boolean containsPrivateKeys(String did) throws DIDStoreException {
		return containsPrivateKeys(DID.valueOf(did));
	}


	/**
	 * Delete the private key owned to the specified key.
	 *
	 * @param did the owner of key
	 * @param id the identifier of key
	 * @return the returned value is true if deleting private keys successfully;
	 *         the returned value is false if deleting private keys failed.
	 * @throws DIDStoreException DIDStore error.
	 */
	public boolean deletePrivateKey(DIDURL id) throws DIDStoreException {
		checkArgument(id != null, "Invalid id");
		cache.invalidate(id);
		return storage.deletePrivateKey(id);
	}

	/**
	 * Delete the private key owned to the specified key.
	 *
	 * @param did the owner of key
	 * @param id the identifier of key
	 * @return the returned value is true if deleting private keys successfully;
	 *         the returned value is false if deleting private keys failed.
	 * @throws DIDStoreException DIDStore error.
	 */
	public boolean deletePrivateKey(String id) throws DIDStoreException {
		return deletePrivateKey(DIDURL.valueOf(id));
	}

	/**
	 * Sign the digest data by the specified key.
	 *
	 * @param did the owner of sign key
	 * @param id the identifier of sign key
	 * @param storepass the password for DIDStore
	 * @param digest the digest data
	 * @return the signature string
	 * @throws DIDStoreException can not get DID Document if no specified sign key.
	 */
	protected String sign(DIDURL id, String storepass, byte[] digest)
			throws DIDStoreException {
		checkArgument(id != null, "Invalid id");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");
		checkArgument(digest != null && digest.length > 0, "Invalid digest");

		HDKey key = HDKey.deserialize(loadPrivateKey(id, storepass));
		byte[] sig = EcdsaSigner.sign(key.getPrivateKeyBytes(), digest);
		key.wipe();

		return Base64.encodeToString(sig,
				Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
	}

    /**
     * Change password for DIDStore.
     *
     * @param oldPassword the old password
     * @param newPassword the new password
     * @throws DIDStoreException DIDStore error.
     */
	public void changePassword(String oldPassword, String newPassword)
			throws DIDStoreException {
		storage.changePassword((data) -> {
			return DIDStore.reEncrypt(data, oldPassword, newPassword);
		});

		metadata.setFingerprint(calcFingerprint(newPassword));
		cache.invalidateAll();
	}

	@JsonPropertyOrder({ "type", "created", "id", "document", "credential", "privatekey", "fingerprint" })
	@JsonInclude(Include.NON_NULL)
	static class DIDExport extends DIDObject<DIDExport> {
		@JsonProperty("type")
		private String type;
		@JsonProperty("created")
		private Date created;
		@JsonProperty("id")
		private DID id;
		@JsonProperty("document")
		private Document document;
		@JsonProperty("credential")
		private List<Credential> credentials;
		@JsonProperty("privatekey")
		private List<PrivateKey> privatekeys;
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
				return null;

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

		public List<PrivateKey> getPrivatekey() {
			return privatekeys;
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

			bytes = Long.toString(created.getTime()).getBytes();
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
			List<DIDURL> ids = listCredentials(did);
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
     * Export DID information into file with json format. The json content
     * include document, credentials, private keys and meta.
	 *
	 * @param did the specified DID
	 * @param out the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void exportDid(DID did, OutputStream out, String password,
			String storepass) throws DIDStoreException, IOException {
		if (did == null || out == null || password == null ||
				password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		try {
			exportDid(did, password, storepass).serialize(out, true);
		} catch (DIDSyntaxException ignore) {
			// Should never happen
			log.error("INTERNAL - Serialize exported private identity", ignore);
		}
	}

	/**
     * Export DID information into file with json format. The json content
     * include document, credentials, private keys and meta.
	 *
	 * @param did the specified DID
	 * @param out the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void exportDid(String did, OutputStream out, String password,
			String storepass) throws DIDStoreException, IOException {
		exportDid(DID.valueOf(did), out, password, storepass);
	}

	/**
     * Export DID information into file with json format. The json content
     *  include document, credentials, private keys and meta.
	 *
	 * @param did the specified DID
	 * @param out the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void exportDid(DID did, Writer out, String password,
			String storepass) throws DIDStoreException, IOException {
		if (did == null || out == null || password == null ||
				password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		try {
			exportDid(did, password, storepass).serialize(out, true);
		} catch (DIDSyntaxException ignore) {
			// Should never happen
			log.error("INTERNAL - Serialize exported private identity", ignore);
		}
	}

	/**
     * Export DID information into file with json format. The json content
     * include document, credentials, private keys and meta.
	 *
	 * @param did the specified DID string
	 * @param out the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void exportDid(String did, Writer out, String password, String storepass)
			throws DIDStoreException, IOException {
		exportDid(DID.valueOf(did), out, password, storepass);
	}

	/**
     * Export DID information into file with json format. The json content
     * include document, credentials, private keys and meta.
	 *
	 * @param did the specified DID
	 * @param file the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void exportDid(DID did, File file, String password, String storepass)
			throws DIDStoreException, IOException {
		if (did == null || file == null || password == null ||
				password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		try {
			exportDid(did, password, storepass).serialize(file, true);
		} catch (DIDSyntaxException ignore) {
			// Should never happen
			log.error("INTERNAL - Serialize exported private identity", ignore);
		}
	}

	/**
     * Export DID information into file with json format. The json content
     * include document, credentials, private keys and meta.
	 *
	 * @param did the specified DID string
	 * @param file the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void exportDid(String did, File file, String password, String storepass)
			throws DIDStoreException, IOException {
		exportDid(DID.valueOf(did), file, password, storepass);
	}

	/**
     * Export DID information into file with json format. The json content
     * include document, credentials, private keys and meta.
	 *
	 * @param did the specified DID
	 * @param file the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void exportDid(DID did, String file, String password, String storepass)
			throws DIDStoreException, IOException {
		if (did == null || file == null || file.isEmpty() || password == null ||
				password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		exportDid(did, new File(file), password, storepass);
	}

	/**
     * Export DID information into file with json format. The json content
     * include document, credentials, private keys and meta.
	 *
	 * @param did the specified DID string
	 * @param file the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
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
		if (vcs != null) {
			for (VerifiableCredential vc : vcs) {
				log.debug("Importing credential {}...", vc.getId().toString());
				storage.storeCredential(vc);
				storage.storeCredentialMetadata(vc.getId(), vc.getMetadata());
			}
		}

		List<DIDExport.PrivateKey> sks = de.getPrivatekey();
		if (sks != null) {
			for (DIDExport.PrivateKey sk : sks) {
				log.debug("Importing private key {}...", sk.getId().toString());
				storage.storePrivateKey(sk.getId(), sk.getKey(password, storepass));
			}
		}
	}

	/**
	 * Import DID information by input.
	 *
	 * @param in the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password for DIDStore
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void importDid(InputStream in, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		if (in == null || password == null || password.isEmpty() ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		DIDExport de;
		try {
			de = DIDExport.parse(in, DIDExport.class);
		} catch (DIDSyntaxException e) {
			throw (MalformedExportDataException)e;
		}
		importDid(de, password, storepass);
	}

	/**
	 * Import DID information by input.
	 *
	 * @param in the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password for DIDStore
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void importDid(Reader in, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		if (in == null || password == null || password.isEmpty() ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		DIDExport de;
		try {
			de = DIDExport.parse(in, DIDExport.class);
		} catch (DIDSyntaxException e) {
			throw (MalformedExportDataException)e;
		}
		importDid(de, password, storepass);
	}

	/**
	 * Import DID information by input.
	 *
	 * @param file the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password for DIDStore
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void importDid(File file, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		if (file == null || password == null || password.isEmpty() ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		DIDExport de;
		try {
			de = DIDExport.parse(file, DIDExport.class);
		} catch (DIDSyntaxException e) {
			throw (MalformedExportDataException)e;
		}
		importDid(de, password, storepass);
	}

	/**
	 * Import DID information by input.
	 *
	 * @param file the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password for DIDStore
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void importDid(String file, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		if (file == null || file.isEmpty() || password == null ||
				password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		importDid(new File(file), password, storepass);
	}

	@JsonPropertyOrder({ "type", "created", "mnemonic", "key", "key.pub", "index", "fingerprint" })
	@JsonInclude(Include.NON_NULL)
	static class RootIdentityExport extends DIDObject<RootIdentityExport> {
		@JsonProperty("type")
		private String type;
		@JsonProperty("created")
		private Date created;
		@JsonProperty("mnemonic")
		private String mnemonic;
		@JsonProperty("key")
		private String key;
		@JsonProperty("key.pub")
		private String pubkey;
		@JsonProperty("index")
		private int index;
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

		public String getKey(String exportpass, String storepass)
				throws DIDStoreException {
			return reEncrypt(key, exportpass, storepass);
		}

		public void setKey(String key, String storepass, String exportpass)
				throws DIDStoreException {
			this.key = reEncrypt(key, storepass, exportpass);
		}

		public String getPubkey() {
			return pubkey;
		}

		public void setPubkey(String pubkey) {
			this.pubkey = pubkey;
		}

		public int getIndex() {
			return index;
		}

		public void setIndex(int index) {
			this.index = index;
		}

		private String calculateFingerprint(String exportpass) {
			SHA256Digest sha256 = new SHA256Digest();
			byte[] bytes = exportpass.getBytes();
			sha256.update(bytes, 0, bytes.length);

			bytes = type.getBytes();
			sha256.update(bytes, 0, bytes.length);

			bytes = Long.toString(created.getTime()).getBytes();
			sha256.update(bytes, 0, bytes.length);

			if (mnemonic != null) {
				bytes = mnemonic.getBytes();
				sha256.update(bytes, 0, bytes.length);
			}

			bytes = key.getBytes();
			sha256.update(bytes, 0, bytes.length);

			if (pubkey != null) {
				bytes = pubkey.getBytes();
				sha256.update(bytes, 0, bytes.length);
			}

			bytes = Integer.toString(index).getBytes();
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

			if (key == null || key.isEmpty())
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

		rie.setKey(storage.loadRootIdentityPrivateKey(id), storepass, password);

		RootIdentity identity = storage.loadRootIdentity(id);
		rie.setPubkey(identity.getPreDerivedPublicKey().serializePublicKeyBase58());

		rie.setIndex(identity.getIndex());
		return rie.seal(password);
	}

	/**
     * Export private identity information into file with json format.
     * The json content include mnemonic(encrypted), extended private key(encrypted),
     * extended public key(if has it, dont't encrypted) and index.
	 *
	 * @param out the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void exportRootIdentity(String id, OutputStream out,
			String password, String storepass)
			throws DIDStoreException, IOException {
		checkArgument(id != null && !id.isEmpty(), "Invalid identity id");
		checkArgument(out != null, "Invalid output stream");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		try {
			exportRootIdentity(id, password, storepass).serialize(out);
		} catch (DIDSyntaxException ignore) {
			// Should never happen
			log.error("INTERNAL - Serialize exported private identity", ignore);
		}
	}

	/**
     * Export private identity information into file with json format.
     * The json content include mnemonic(encrypted), extended private key(encrypted),
     * extended public key(if has it, dont't encrypted) and index.
	 *
	 * @param out the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void exportRootIdentity(String id, Writer out,
			String password, String storepass)
			throws DIDStoreException, IOException {
		checkArgument(id != null && !id.isEmpty(), "Invalid identity id");
		checkArgument(out != null, "Invalid output writer");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		try {
			exportRootIdentity(id, password, storepass).serialize(out);
		} catch (DIDSyntaxException ignore) {
			// Should never happen
			log.error("INTERNAL - Serialize exported private identity", ignore);
		}
	}

	/**
     * Export private identity information into file with json format.
     * The json content include mnemonic(encrypted), extended private key(encrypted),
     * extended public key(if has it, dont't encrypted) and index.
	 *
	 * @param file the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void exportRootIdentity(String id, File file,
			String password, String storepass)
			throws DIDStoreException, IOException {
		checkArgument(id != null && !id.isEmpty(), "Invalid identity id");
		checkArgument(file != null, "Invalid output file");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		try {
			exportRootIdentity(id, password, storepass).serialize(file);
		} catch (DIDSyntaxException ignore) {
			// Should never heppen
			log.error("INTERNAL - Serialize exported private identity", ignore);
		}
	}

	/**
     * Export private identity information into file with json format.
     * The json content include mnemonic(encrypted), extended private key(encrypted),
     * extended public key(if has it, dont't encrypted) and index.
	 *
	 * @param file the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void exportRootIdentity(String id, String file,
			String password, String storepass)
			throws DIDStoreException, IOException {
		checkArgument(id != null && !id.isEmpty(), "Invalid identity id");
		checkArgument(file != null && !file.isEmpty(), "Invalid output file");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		exportRootIdentity(id, new File(file), password, storepass);
	}

	private void importRootIdentity(RootIdentityExport rie, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		rie.verify(password);

		// Save
		String encryptedMnemonic = rie.getMnemonic(password, storepass);
		String encryptedPrivateKey = (rie.getKey(password, storepass));
		String publicKey = rie.getPubkey();
		HDKey pk = HDKey.deserializeBase58(publicKey);
		String id = RootIdentity.getId(pk.serializePublicKey());

		storage.storeRootIdentity(id, encryptedMnemonic, encryptedPrivateKey,
				publicKey, rie.getIndex());
	}


	/**
     * Import private identity by input.
	 *
	 * @param in the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password to DIDStore
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
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
     * Import private identity by input.
	 *
	 * @param in the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password to DIDStore
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
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
     * Import private identity by input.
	 *
	 * @param file the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password to DIDStore
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
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
     * Import private identity by input.
	 *
	 * @param file the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password to DIDStore
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void importRootIdentity(String file, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		checkArgument(file != null && !file.isEmpty(), "Invalid input file");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		importRootIdentity(new File(file), password, storepass);
	}

	/**
	 * Export all store information.
	 *
	 * @param out the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void exportStore(ZipOutputStream out, String password,
			String storepass) throws DIDStoreException, IOException {
		checkArgument(out != null, "Invalid output zip stream");
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
	 * Export all store information to zip file.
	 *
	 * @param zipFile the export zip file
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void exportStore(File zipFile, String password, String storepass)
			throws DIDStoreException, IOException {
		checkArgument(zipFile != null, "Invalid output zip file");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		ZipOutputStream out = new ZipOutputStream(new FileOutputStream(zipFile));
		exportStore(out, password, storepass);
		out.close();
	}

	/**
	 * Export all store information to zip file.
	 *
	 * @param zipFile the export zip file
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void exportStore(String zipFile, String password, String storepass)
			throws DIDStoreException, IOException {
		checkArgument(zipFile != null && !zipFile.isEmpty(), "Invalid output zip file");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		exportStore(new File(zipFile), password, storepass);
	}

	/**
	 * Import Store information from input.
	 *
	 * @param in the import input
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void importStore(ZipInputStream in, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		checkArgument(in != null, "Invalid input zip stream");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		ZipEntry ze;
		while ((ze = in.getNextEntry()) != null) {
			if (ze.getName().startsWith("rootIdentity"))
				importRootIdentity(in, password, storepass);
			else
				importDid(in, password, storepass);
			in.closeEntry();
		}
	}

	/**
	 * Import Store information from zip file.
	 *
	 * @param zipFile the import zip file
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void importStore(File zipFile, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		checkArgument(zipFile != null, "Invalid input zip file");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		ZipInputStream in = new ZipInputStream(new FileInputStream(zipFile));
		importStore(in, password, storepass);
		in.close();
	}

	/**
	 * Import Store information from zip file.
	 *
	 * @param zipFile the import zip file
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws MalformedExportDataException if the exported data is invalid
	 * @throws DIDStoreException DIDStore error
	 * @throws IOException write json string failed
	 */
	public void importStore(String zipFile, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		checkArgument(zipFile != null && !zipFile.isEmpty(), "Invalid input zip file");
		checkArgument(password != null && !password.isEmpty(), "Invalid password");
		checkArgument(storepass != null && !storepass.isEmpty(), "Invalid storepass");

		importStore(new File(zipFile), password, storepass);
	}
}
