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
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.elastos.did.DIDDocument.PublicKey;
import org.elastos.did.DIDStorage.ReEncryptor;
import org.elastos.did.crypto.Aes256cbc;
import org.elastos.did.crypto.Base58;
import org.elastos.did.crypto.Base64;
import org.elastos.did.crypto.EcdsaSigner;
import org.elastos.did.crypto.HDKey;
import org.elastos.did.exception.DIDBackendException;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.MalformedDIDException;
import org.elastos.did.exception.MalformedDocumentException;
import org.elastos.did.exception.MalformedExportDataException;
import org.elastos.did.exception.WrongPasswordException;
import org.elastos.did.util.LRUCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.digests.SHA256Digest;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * DIDStore is local store for all DIDs.
 */
public final class DIDStore {
	private static final int CACHE_INITIAL_CAPACITY = 16;
	private static final int CACHE_MAX_CAPACITY = 32;

	/**
	 * List DIDs that contains private key in DIDStore
	 */
	public static final int DID_HAS_PRIVATEKEY = 0;

	/**
	 * List DIDs that does not contain private key in DIDStore
	 */
	public static final int DID_NO_PRIVATEKEY = 1;

	/**
	 * List all DIDs
	 */
	public static final int DID_ALL	= 2;

	private static final String DID_EXPORT = "did.elastos.export/1.0";

	private Map<DID, DIDDocument> didCache;
	private Map<DIDURL, VerifiableCredential> vcCache;

	private DIDStorage storage;

	private static final Logger log = LoggerFactory.getLogger(DIDStore.class);

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

	private DIDStore(int initialCacheCapacity, int maxCacheCapacity, DIDStorage storage) {
		if (maxCacheCapacity > 0) {
			this.didCache = LRUCache.createInstance(initialCacheCapacity, maxCacheCapacity);
			this.vcCache = LRUCache.createInstance(initialCacheCapacity, maxCacheCapacity);
		}

		this.storage = storage;
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
	public static DIDStore open(String type, String location,
			int initialCacheCapacity, int maxCacheCapacity) throws DIDStoreException {
		if (type == null || location == null || location.isEmpty() ||
				maxCacheCapacity < initialCacheCapacity)
			throw new IllegalArgumentException();

		if (!type.equals("filesystem"))
			throw new DIDStoreException("Unsupported store type: " + type);

		DIDStorage storage = new FileSystemStorage(location);
		return new DIDStore(initialCacheCapacity, maxCacheCapacity, storage);
	}

	/**
	 * Initialize or check the DIDStore.
	 *
	 * @param type the type for different file system
	 * @param location the location of DIDStore
	 * @return the DIDStore object
	 * @throws DIDStoreException Unsupport the specified store type.
	 */
	public static DIDStore open(String type, String location)
			throws DIDStoreException {
		return open(type, location, CACHE_INITIAL_CAPACITY, CACHE_MAX_CAPACITY);
	}

	/**
	 * Judge whether private identity exists in DIDStore.
	 *
	 * @return the returned value is true if private identity exists;
	 *         the returned value if false if private identity doesnot exist.
	 * @throws DIDStoreException Unsupport the specified store type.
	 */
	public boolean containsPrivateIdentity() throws DIDStoreException {
		return storage.containsPrivateIdentity();
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
		byte[] cipher;
		try {
			cipher = Aes256cbc.encrypt(input, passwd);
		} catch (CryptoException e) {
			throw new DIDStoreException("Encrypt data error.", e);
		}

		return Base64.encodeToString(cipher,
				Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
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
		byte[] cipher = Base64.decode(input,
				Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
		try {
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

	/**
	 * Initialize private identity by mnemonic.
	 *
	 * @param language the language string
     *                support language string: "chinese_simplified",
     *                "chinese_traditional", "czech", "english", "french",
     *                "italian", "japanese", "korean", "spanish".
	 * @param mnemonic the mnemonic string
	 * @param passphrase the password for mnemonic to generate seed
	 * @param storepass the password for DIDStore
	 * @param force force = true, must create new private identity;
	 *              force = false, must not create new private identity if there is private identity.
	 * @throws DIDStoreException there is private identity if user need unforce mode.
	 */
	public void initPrivateIdentity(String language, String mnemonic,
			String passphrase, String storepass, boolean force)
			throws DIDStoreException {
		if (mnemonic == null)
			throw new IllegalArgumentException("Invalid mnemonic.");

		if (storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException("Invalid password.");

		try {
			Mnemonic mc = Mnemonic.getInstance(language);
			if (!mc.isValid(mnemonic))
				throw new IllegalArgumentException("Invalid mnemonic.");
		} catch (DIDException e) {
			throw new IllegalArgumentException(e);
		}

		if (containsPrivateIdentity() && !force)
			throw new DIDStoreException("Already has private identity.");

		if (passphrase == null)
			passphrase = "";

		HDKey privateIdentity = new HDKey(mnemonic, passphrase);

		initPrivateIdentity(privateIdentity, storepass);

		// Save mnemonic
		String encryptedMnemonic = encryptToBase64(
				mnemonic.getBytes(), storepass);
		storage.storeMnemonic(encryptedMnemonic);

	}

	/**
	 * Initialize new private identity by mnemonic with unforce mode.
	 *
	 * @param language the language string
     *                support language string: "chinese_simplified",
     *                "chinese_traditional", "czech", "english", "french",
     *                "italian", "japanese", "korean", "spanish".
	 * @param mnemonic the mnemonic string
	 * @param passphrase the password for mnemonic to generate seed
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException there is private identity if user need unforce mode.
	 */
	public void initPrivateIdentity(String language, String mnemonic,
			String passphrase, String storepass) throws DIDStoreException {
		initPrivateIdentity(language, mnemonic, passphrase, storepass, false);
	}

	/**
	 * Initialize private identity by extended private key.
	 *
	 * @param extentedPrivateKey the extented private key string
	 * @param storepass the password for DIDStore
	 * @param force force = true, must create new private identity;
	 *              force = false, must not create new private identity if there is private identity.
	 * @throws DIDStoreException there is private identity if user need unforce mode.
	 */
	public void initPrivateIdentity(String extentedPrivateKey, String storepass,
			boolean force) throws DIDStoreException {
		if (extentedPrivateKey == null || extentedPrivateKey.isEmpty())
			throw new IllegalArgumentException("Invalid extended private key.");

		if (storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException("Invalid password.");

		if (containsPrivateIdentity() && !force)
			throw new DIDStoreException("Already has private indentity.");

		HDKey privateIdentity = HDKey.deserialize(Base58.decode(extentedPrivateKey));
		initPrivateIdentity(privateIdentity, storepass);
	}

	/**
	 * Initialize private identity by extended private key with unforce mode.
	 *
	 * @param extentedPrivateKey the extented private key string
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException there is private identity if user need unforce mode.
	 */
	public void initPrivateIdentity(String extentedPrivateKey, String storepass)
			throws DIDStoreException {
		initPrivateIdentity(extentedPrivateKey, storepass, false);
	}

	/**
	 * Initialize private identity by HDKey content.
	 *
	 * @param privateIdentity the HDKey object
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException there is private identity if user need unforce mode.
	 */
	private void initPrivateIdentity(HDKey privateIdentity, String storepass)
			throws DIDStoreException {
		// Save extended root private key
		String encryptedIdentity = encryptToBase64(
				privateIdentity.serialize(), storepass);
		storage.storePrivateIdentity(encryptedIdentity);

		// Save pre-derived public key
		HDKey preDerivedKey = privateIdentity.derive(HDKey.PRE_DERIVED_PUBLICKEY_PATH);
		storage.storePublicIdentity(preDerivedKey.serializePublicKeyBase58());

		// Save index
		storage.storePrivateIdentityIndex(0);

		preDerivedKey.wipe();
		privateIdentity.wipe();
	}

	/**
	 * Export mnemonic from DIDStore
	 *
	 * @param storepass the password for DIDStore
 	 * @return the mnemonic string
	 * @throws DIDStoreException there is no mnemonic in DID Store.
	 */
	public String exportMnemonic(String storepass) throws DIDStoreException {
		if (storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException("Invalid password.");

		if (storage.containsMnemonic()) {
			String encryptedMnemonic = storage.loadMnemonic();
			return new String(decryptFromBase64(encryptedMnemonic, storepass));
		} else {
			throw new DIDStoreException("DID store doesn't contain mnemonic.");
		}
	}

    /**
     * Load private identity from DIDStore.
     *
     * @param storepass the password for DIDStore
     * @return the HDKey object(private identity)
     * @throws DIDStoreException there is invalid private identity in DIDStore.
     */
	protected HDKey loadPrivateIdentity(String storepass)
			throws DIDStoreException {
		if (!containsPrivateIdentity())
			return null;

		HDKey privateIdentity = null;

		byte[] keyData = decryptFromBase64(storage.loadPrivateIdentity(), storepass);
		if (keyData.length == HDKey.SEED_BYTES) {
			// For backward compatible, convert to extended root private key
			// TODO: Should be remove in the future
			privateIdentity = new HDKey(keyData);

			String encryptedIdentity = encryptToBase64(
					privateIdentity.serialize(), storepass);
			storage.storePrivateIdentity(encryptedIdentity);
		} else if (keyData.length == HDKey.EXTENDED_PRIVATEKEY_BYTES){
			privateIdentity = HDKey.deserialize(keyData);
		} else {
			throw new DIDStoreException("Invalid private identity.");
		}

		Arrays.fill(keyData, (byte)0);

		// For backward compatible, create pre-derived public key if not exist.
		// TODO: Should be remove in the future
		if (!storage.containsPublicIdentity()) {
			HDKey preDerivedKey = privateIdentity.derive(HDKey.PRE_DERIVED_PUBLICKEY_PATH);
			storage.storePublicIdentity(preDerivedKey.serializePublicKeyBase58());
		}

		return privateIdentity;
	}

	/**
	 * Load public identity from identity.
	 * There is extended private key and extended public key in DIDStore.
	 *
	 * @return the HDKey object
	 * @throws DIDStoreException load root public identity failed.
	 */
	protected HDKey loadPublicIdentity() throws DIDStoreException {
		if (!containsPrivateIdentity())
			return null;

		String keyData = storage.loadPublicIdentity();
		HDKey publicIdentity = HDKey.deserializeBase58(keyData);

		return publicIdentity;
	}

	/**
	 * Synchronize DIDStore.
	 *
	 * @param handle the handle to ConflictHandle
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException synchronize did faile with resolve error.
	 * @throws DIDStoreException there is no private identity in DIDStore.
	 */
	public void synchronize(ConflictHandle handle, String storepass)
			throws DIDBackendException, DIDStoreException {
		if (handle == null || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		int nextIndex = storage.loadPrivateIdentityIndex();
		HDKey privateIdentity = loadPrivateIdentity(storepass);
		if (privateIdentity == null)
			throw new DIDStoreException("DID Store does not contains private identity.");

		try {
			int blanks = 0;
			int i = 0;

			while (i < nextIndex || blanks < 20) {
				HDKey key = privateIdentity.derive(HDKey.DERIVE_PATH_PREFIX + i++);
				DID did = new DID(DID.METHOD, key.getAddress());

				log.info("Synchronize {}/{}...", did.toString(), i);

				try {
					DIDDocument chainCopy = null;
					chainCopy = DIDBackend.getInstance().resolveDid(did, true);
					if (chainCopy != null) {
						log.debug("{} exists, got the on-chain copy.", did.toString());

						DIDDocument finalCopy = chainCopy;

						DIDDocument localCopy = loadDid(did);
						if (localCopy != null) {
							if (localCopy.getMetadata().getSignature() == null ||
									!localCopy.getProof().getSignature().equals(
									localCopy.getMetadata().getSignature())) {
								log.debug("{} on-chain copy conflict with local copy.",
										did.toString());

								// Local copy was modified
								finalCopy = handle.merge(chainCopy, localCopy);
								if (finalCopy == null || !finalCopy.getSubject().equals(did)) {
									log.error("Conflict handle merge the DIDDocument error.");
									throw new DIDStoreException("deal with local modification error.");
								} else {
									log.debug("Conflict handle return the final copy.");
								}
							}
						}

						// Save private key
						storePrivateKey(did, finalCopy.getDefaultPublicKeyId(),
								key.serialize(), storepass);

						storeDid(finalCopy);

						if (i >= nextIndex)
							storage.storePrivateIdentityIndex(i);

						blanks = 0;
					} else {
						log.debug("{} not exists.", did.toString());

						if (i >= nextIndex)
							blanks++;
					}
				} finally {
					key.wipe();
				}
			}
		} finally {
			privateIdentity.wipe();
		}
	}

	/**
	 * Synchronize DIDStore.
	 * ConflictHandle uses default method.
	 *
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException synchronize did faile with resolve error.
	 * @throws DIDStoreException there is no private identity in DIDStore.
	 */
	public void synchronize(String storepass)
			throws DIDBackendException, DIDStoreException {
		synchronize((c, l) -> {
			l.getMetadata().setPublished(c.getMetadata().getPublished());
			l.getMetadata().setSignature(c.getMetadata().getSignature());
			return l;
		}, storepass);
	}

    /**
     * Synchronize DIDStore with asynchronous mode.
     *
	 * @param handle the handle to ConflictHandle
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, the result is the DIDDocument interface for
	 *         resolved DIDDocument if success; null otherwise.
     */
	public CompletableFuture<Void> synchronizeAsync(
			ConflictHandle handle, String storepass) {
		if (handle == null || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				synchronize(handle, storepass);
			} catch (DIDBackendException | DIDStoreException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

    /**
     * Synchronize DIDStore with asynchronous mode.
     * ConflictHandle uses default method.
     *
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
     */
	public CompletableFuture<Void> synchronizeAsync(String storepass) {
		if (storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				synchronize(storepass);
			} catch (DIDBackendException | DIDStoreException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Create a new DID with specified index and get this DID's Document content.
	 *
	 * @param index the index to create new did.
	 * @param alias the alias string
	 * @param storepass the password for DIDStore
	 * @return the DIDDocument content related to the new DID
	 * @throws DIDStoreException there is no private identity in DIDStore.
	 */
	public DIDDocument newDid(int index, String alias, String storepass)
			throws DIDStoreException {
		if (index < 0 || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		HDKey privateIdentity = loadPrivateIdentity(storepass);
		if (privateIdentity == null)
			throw new DIDStoreException("DID Store not contains private identity.");

		HDKey key = privateIdentity.derive(HDKey.DERIVE_PATH_PREFIX + index);
		try {
			DID did = new DID(DID.METHOD, key.getAddress());
			log.info("Creating new DID {} with index {}...", did.toString(), index);

			DIDDocument doc = loadDid(did);
			if (doc != null)
				throw new DIDStoreException("DID already exists.");

			DIDURL id = new DIDURL(did, "primary");
			storePrivateKey(did, id, key.serialize(), storepass);

			DIDDocument.Builder db = new DIDDocument.Builder(did, this);
			db.addAuthenticationKey(id, key.getPublicKeyBase58());
			try {
				doc = db.seal(storepass);
			} catch (MalformedDocumentException ignore) {
				log.error("INTERNAL - Seal DID document", ignore);
				throw new DIDStoreException(ignore);
			}
			doc.getMetadata().setAlias(alias);
			storeDid(doc);
			return doc;
		} finally {
			privateIdentity.wipe();
			key.wipe();
		}
	}

	/**
	 * Create a new DID with specified index and get this DID's Document content.
	 *
	 * @param index the index to create new did.
	 * @param storepass the password for DIDStore
	 * @return the DIDDocument content related to the new DID
	 * @throws DIDStoreException there is no private identity in DIDStore.
	 */
	public DIDDocument newDid(int index, String storepass) throws DIDStoreException {
		return newDid(index, null, storepass);
	}

	/**
	 * Create a new DID and get this DID's Document content.
	 *
	 * @param alias the alias string
	 * @param storepass the password for DIDStore
	 * @return the DIDDocument content related to the new DID
	 * @throws DIDStoreException there is no private identity in DIDStore.
	 */
	public DIDDocument newDid(String alias, String storepass)
			throws DIDStoreException {
		int nextIndex = storage.loadPrivateIdentityIndex();
		DIDDocument doc = newDid(nextIndex++, alias, storepass);
		storage.storePrivateIdentityIndex(nextIndex);
		return doc;
	}

	/**
	 * Create a new DID without alias and get this DID's Document content.
	 *
	 * @param storepass the password for DIDStore
	 * @return the DIDDocument content related to the new DID
	 * @throws DIDStoreException there is no private identity in DIDStore.
	 */
	public DIDDocument newDid(String storepass) throws DIDStoreException {
		return newDid(null, storepass);
	}

	/**
	 * Only get DID with specified index.
	 *
	 * @param index the index
	 * @return the DID object
	 * @throws DIDStoreException there is no private identity in DIDStore.
	 */
	public DID getDid(int index) throws DIDStoreException {
		if (index < 0)
			throw new IllegalArgumentException();

		HDKey publicIdentity = loadPublicIdentity();
		if (publicIdentity == null)
			throw new DIDStoreException("DID Store not contains private identity.");

		HDKey key = publicIdentity.derive("0/" + index);
		DID did = new DID(DID.METHOD, key.getAddress());
		return did;
	}

	public DIDDocument newDid(DID did, DID controller, String storepass)
			throws DIDStoreException {
		if (did == null || controller == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		log.info("Creating new DID {} with controller {}...", did, controller);

		DIDDocument controllerDoc = loadDid(controller);
		if (controllerDoc == null)
			throw new DIDStoreException("Controller DID not exists in the store");

		if (!controllerDoc.isValid())
			throw new DIDStoreException("Controller DID not valid");

		if (loadDid(did) != null)
			throw new DIDStoreException("DID " + did + " already exists.");

		try {
			if (did.resolve(true) != null)
				throw new DIDStoreException("DID " + did + " already exist.");
		} catch (DIDResolveException ignore) {
			// If already exist, the ID transaction will failed in the future
		}

		DIDDocument.Builder db = new DIDDocument.Builder(did, controllerDoc, this);
		try {
			DIDDocument doc = db.seal(storepass);
			storeDid(doc);
			return doc;
		} catch (MalformedDocumentException ignore) {
			log.error("INTERNAL - Seal DID document", ignore);
			throw new DIDStoreException(ignore);
		}
	}

	public DIDDocument newDid(String did, String controller, String storepass)
			throws DIDStoreException {
		try {
			return newDid(new DID(did), new DID(controller), storepass);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public DIDDocument newDid(DID did, DID[] controllers, DID self, int multisig, String storepass)
			throws DIDStoreException, DIDResolveException {
		if (did == null || controllers == null || controllers.length == 0 ||
				self == null ||storepass.isEmpty())
			throw new IllegalArgumentException();

		log.info("Creating new DID {} with controllers {}...", did, controllers);

		DIDDocument controllerDoc = loadDid(self);
		if (controllerDoc == null)
			throw new DIDStoreException("Controller DID not exists in the store");

		if (!controllerDoc.isValid())
			throw new DIDStoreException("Controller DID not valid");

		if (loadDid(did) != null)
			throw new DIDStoreException("DID " + did + " already exists.");

		try {
			if (did.resolve(true) != null)
				throw new DIDStoreException("DID " + did + " already exist.");
		} catch (DIDResolveException ignore) {
			// If already exist, the ID transaction will failed in the future
		}

		DIDDocument.Builder db = new DIDDocument.Builder(did, controllerDoc, this);
		try {
			for (DID ctrl : controllers) {
				if (ctrl.equals(self))
					continue;

				db.addController(ctrl);
			}

			db.setMultiSignature(multisig);

			DIDDocument doc = db.seal(storepass);
			storeDid(doc);
			return doc;
		} catch (MalformedDocumentException ignore) {
			log.error("INTERNAL - Seal DID document", ignore);
			throw new DIDStoreException(ignore);
		}
	}

	public DIDDocument newDid(String did, String controllers[], String self, int multisig, String storepass)
			throws DIDStoreException, DIDResolveException {
		if (did == null || controllers == null || controllers.length == 0 ||
				self == null ||storepass.isEmpty())
			throw new IllegalArgumentException();

		try {
			List<DID> _controllers = new ArrayList<DID>();
			for (String ctrl : controllers)
				_controllers.add(new DID(ctrl));


			return newDid(new DID(did), _controllers.toArray(new DID[0]), new DID(self), multisig, storepass);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}
	}

    /**
     * Store DID Document in the DIDStore.
     *
     * @param doc the DIDDocument object
     * @throws DIDStoreException DIDStore error.
     */
	public void storeDid(DIDDocument doc) throws DIDStoreException {
		if (doc == null)
			throw new IllegalArgumentException();

		storage.storeDid(doc);

		DIDMetadata metadata = loadDidMetadata(doc.getSubject());
		doc.getMetadata().merge(metadata);
		doc.getMetadata().setStore(this);

		storage.storeDidMetadata(doc.getSubject(), doc.getMetadata());

		for (VerifiableCredential vc : doc.getCredentials())
			storeCredential(vc);

		if (didCache != null)
			didCache.put(doc.getSubject(), doc);
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
		storage.storeDidMetadata(did, metadata);

		if (didCache != null) {
			DIDDocument doc = didCache.get(did);
			if (doc != null)
				doc.setMetadata(metadata);
		}
	}

	/**
	 * Store DID Metadata.
	 *
	 * @param did the owner of Metadata
	 * @param metadata the meta data
	 * @throws DIDStoreException DIDStore error.
	 */
	protected void storeDidMetadata(String did, DIDMetadata metadata)
			throws DIDStoreException{
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		storeDidMetadata(_did, metadata);
	}

	/**
	 * Load Meta data for the specified DID.
	 *
	 * @param did the specified DID
	 * @return the Meta data
	 * @throws DIDStoreException DIDStore error.
	 */
	protected DIDMetadata loadDidMetadata(DID did) throws DIDStoreException {
		if (did == null)
			throw new IllegalArgumentException();

		DIDMetadata metadata = null;
		DIDDocument doc = null;

		if (didCache != null) {
			doc = didCache.get(did);
			if (doc != null) {
				metadata = doc.getMetadata();
				if (metadata != null)
					return metadata;
			}
		}

		metadata = storage.loadDidMetadata(did);
		if (doc != null)
			doc.setMetadata(metadata);

		return metadata;
	}

	/**
	 * Load Meta data about DID.
	 *
	 * @param did the specified DID string
	 * @return the Meta data
	 * @throws DIDStoreException DIDStore error.
	 */
	protected DIDMetadata loadDidMetadata(String did) throws DIDStoreException {
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		return loadDidMetadata(_did);
	}

	/**
	 * Load the specified DID content(DIDDocument).
	 *
	 * @param did the specified DID
	 * @return the DIDDocument object
	 * @throws DIDStoreException DIDStore error.
	 */
	public DIDDocument loadDid(DID did) throws DIDStoreException {
		if (did == null)
			throw new IllegalArgumentException();

		DIDDocument doc;

		if (didCache != null) {
			doc = didCache.get(did);
			if (doc != null)
				return doc;
		}

		doc = storage.loadDid(did);
		if (doc != null) {
			DIDMetadata metadata = storage.loadDidMetadata(did);
			metadata.setStore(this);
			doc.setMetadata(metadata);
		}

		if (doc != null && didCache != null)
			didCache.put(doc.getSubject(), doc);

		return doc;
	}

	/**
	 * Load the specified DID content(DIDDocument).
	 *
	 * @param did the specified DID string
	 * @return the DIDDocument object
	 * @throws DIDStoreException DIDStore error.
	 */
	public DIDDocument loadDid(String did) throws DIDStoreException {
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		return loadDid(_did);
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
		if (did == null)
			throw new IllegalArgumentException();

		return storage.containsDid(did);
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
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		return containsDid(_did);
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
		if (did == null)
			throw new IllegalArgumentException();

		didCache.remove(did);
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
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		return deleteDid(_did);
	}

	/**
	 * List all DIDs according to the specified condition.
	 *
	 * @param filter the specified condition.
	 *               0: all did; 1: did has privatekeys;
     *               2: did has no privatekeys.
	 * @return the DID array.
	 * @throws DIDStoreException DIDStore error.
	 */
	public List<DID> listDids(int filter) throws DIDStoreException {
		List<DID> dids = storage.listDids(filter);

		for (DID did : dids) {
			DIDMetadata metadata = loadDidMetadata(did);
			metadata.setStore(this);
			did.setMetadata(metadata);
		}

		return dids;
	}

	/**
	 * Store the specified Credential.
	 *
	 * @param credential the Credential object
	 * @throws DIDStoreException DIDStore error.
	 */
	public void storeCredential(VerifiableCredential credential)
			throws DIDStoreException {
		if (credential == null)
			throw new IllegalArgumentException();

		storage.storeCredential(credential);

		CredentialMetadata metadata = loadCredentialMetadata(
				credential.getSubject().getId(), credential.getId());
		credential.getMetadata().merge(metadata);
		credential.getMetadata().setStore(this);

		storage.storeCredentialMetadata(credential.getSubject().getId(),
				credential.getId(), credential.getMetadata());

		if (vcCache != null)
			vcCache.put(credential.getId(), credential);
	}

    /**
     * Store meta data for the specified Credential.
     *
     * @param did the owner of the specified Credential
     * @param id the identifier of Credential
     * @param metadata the meta data for Credential
     * @throws DIDStoreException DIDStore error.
     */
	protected void storeCredentialMetadata(DID did, DIDURL id,
			CredentialMetadata metadata) throws DIDStoreException {
		if (did == null || id == null)
			throw new IllegalArgumentException();

		storage.storeCredentialMetadata(did, id, metadata);

		if (vcCache != null) {
			VerifiableCredential vc = vcCache.get(id);
			if (vc != null) {
				vc.setMetadata(metadata);
			}
		}
	}

    /**
     * Store meta data for the specified Credential.
     *
     * @param did the owner of the specified Credential
     * @param id the identifier of Credential
     * @param metadata the meta data for Credential
     * @throws DIDStoreException DIDStore error.
     */
	protected void storeCredentialMetadata(String did, String id,
			CredentialMetadata metadata) throws DIDStoreException {
		DID _did = null;
		DIDURL _id = null;
		try {
			_did = new DID(did);
			_id = new DIDURL(_did, id);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		storeCredentialMetadata(_did, _id, metadata);
	}

	/**
	 * Load the meta data about the specified Credential.
	 *
	 * @param did the owner of Credential
     * @param id the identifier of Credential
	 * @return the meta data for Credential
	 * @throws DIDStoreException DIDStore error.
	 */
	protected CredentialMetadata loadCredentialMetadata(DID did, DIDURL id)
			throws DIDStoreException {
		if (did == null || id == null)
			throw new IllegalArgumentException();

		CredentialMetadata metadata = null;
		VerifiableCredential vc = null;

		if (vcCache != null) {
			vc = vcCache.get(id);
			if (vc != null) {
				metadata = vc.getMetadata();
				if (metadata != null)
					return metadata;
			}
		}

		metadata = storage.loadCredentialMetadata(did, id);
		if (vc != null)
			vc.setMetadata(metadata);

		return metadata;
	}

	/**
	 * Load the meta data about the specified Credential.
	 *
	 * @param did the owner of Credential
     * @param id the identifier of Credential
	 * @return the meta data for Credential
	 * @throws DIDStoreException DIDStore error.
	 */
	protected CredentialMetadata loadCredentialMetadata(String did, String id)
			throws DIDStoreException {
		DID _did = null;
		DIDURL _id = null;
		try {
			_did = new DID(did);
			_id = new DIDURL(_did, id);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		return loadCredentialMetadata(_did, _id);
	}

	/**
	 * Load the specified Credential.
	 *
	 * @param did the owner of Credential
	 * @param id the identifier of Credential
	 * @return the Credential object
	 * @throws DIDStoreException DIDStore error.
	 */
	public VerifiableCredential loadCredential(DID did, DIDURL id)
			throws DIDStoreException {
		if (did == null || id == null)
			throw new IllegalArgumentException();

		VerifiableCredential vc;

		if (vcCache != null) {
			vc = vcCache.get(id);
			if (vc != null)
				return vc;
		}

		vc = storage.loadCredential(did, id);
		if (vc != null) {
			CredentialMetadata metadata = storage.loadCredentialMetadata(did, id);
			metadata.setStore(this);
			vc.setMetadata(metadata);
		}

		if (vc != null && vcCache != null)
			vcCache.put(vc.getId(), vc);

		return vc;
	}

	/**
	 * Load the specified Credential.
	 *
	 * @param did the owner of Credential
	 * @param id the identifier of Credential
	 * @return the Credential object
	 * @throws DIDStoreException DIDStore error.
	 */
	public VerifiableCredential loadCredential(String did, String id)
			throws DIDStoreException {
		DID _did = null;
		DIDURL _id = null;
		try {
			_did = new DID(did);
			_id = new DIDURL(_did, id);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		return loadCredential(_did, _id);
	}

	/**
	 * Judge whether does DIDStore contain any credential owned the specific DID.
	 *
	 * @param did the owner of Credential
	 * @return the returned value is true if there is no credential owned the specific DID.
	 * @throws DIDStoreException DIDStore error.
	 */
	public boolean containsCredentials(DID did) throws DIDStoreException {
		if (did == null)
			throw new IllegalArgumentException();

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
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		return containsCredentials(_did);
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
	public boolean containsCredential(DID did, DIDURL id)
			throws DIDStoreException {
		if (did == null || id == null)
			throw new IllegalArgumentException();

		return storage.containsCredential(did, id);
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
	public boolean containsCredential(String did, String id)
			throws DIDStoreException {
		DID _did = null;
		DIDURL _id = null;
		try {
			_did = new DID(did);
			_id = new DIDURL(_did, id);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		return containsCredential(_did, _id);
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
	public boolean deleteCredential(DID did, DIDURL id) throws DIDStoreException {
		if (did == null || id == null)
			throw new IllegalArgumentException();

		vcCache.remove(id);
		return storage.deleteCredential(did, id);
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
	public boolean deleteCredential(String did, String id)
			throws DIDStoreException {
		DID _did = null;
		DIDURL _id = null;
		try {
			_did = new DID(did);
			_id = new DIDURL(_did, id);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		return deleteCredential(_did, _id);
	}

	/**
	 * List the Credentials owned the specified DID.
	 *
	 * @param did the owner of Credential
	 * @return the Credential array owned the specified DID.
	 * @throws DIDStoreException DIDStore error.
	 */
	public List<DIDURL> listCredentials(DID did) throws DIDStoreException {
		if (did == null)
			throw new IllegalArgumentException();

		List<DIDURL> ids = storage.listCredentials(did);

		for (DIDURL id : ids) {
			CredentialMetadata metadata = loadCredentialMetadata(did, id);
			metadata.setStore(this);
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
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		return listCredentials(_did);
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
	public List<DIDURL> selectCredentials(DID did, DIDURL id, String[] type)
			throws DIDStoreException {
		if (did == null)
			throw new IllegalArgumentException();

		if ((id == null) && (type == null || type.length == 0))
			throw new IllegalArgumentException();

		return storage.selectCredentials(did, id, type);
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
	public List<DIDURL> selectCredentials(String did, String id, String[] type)
			throws DIDStoreException {
		if (did == null || did.isEmpty())
			throw new IllegalArgumentException();

		if ((id == null || id.isEmpty()) && type == null || type.length == 0)
			throw new IllegalArgumentException();

		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		DIDURL _id = id == null ? null : new DIDURL(_did, id);
		return selectCredentials(_did, _id, type);
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
	public void storePrivateKey(DID did, DIDURL id, byte[] privateKey,
			String storepass) throws DIDStoreException {
		if (did == null || id == null ||
				privateKey == null || privateKey.length == 0 ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		String encryptedKey = encryptToBase64(privateKey, storepass);
		storage.storePrivateKey(did, id, encryptedKey);
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
	public void storePrivateKey(String did, String id, byte[] privateKey,
			String storepass) throws DIDStoreException {
		DID _did = null;
		DIDURL _id = null;
		try {
			_did = new DID(did);
			_id = new DIDURL(_did, id);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		storePrivateKey(_did, _id, privateKey, storepass);
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
	protected byte[] loadPrivateKey(DID did, DIDURL id, String storepass)
			throws DIDStoreException {
		String encryptedKey = storage.loadPrivateKey(did, id);
		byte[] keyBytes = decryptFromBase64(encryptedKey, storepass);

		// For backward compatible, convert to extended private key
		// TODO: Should be remove in the future
		byte[] extendedKeyBytes = null;
		if (keyBytes.length == HDKey.PRIVATEKEY_BYTES) {
			HDKey identity = loadPrivateIdentity(storepass);
			if (identity != null) {
				for (int i = 0; i < 100; i++) {
					HDKey child = identity.derive(HDKey.DERIVE_PATH_PREFIX + i);
					if (Arrays.equals(child.getPrivateKeyBytes(), keyBytes)) {
						extendedKeyBytes = child.serialize();
						break;
					}
					child.wipe();
				}
				identity.wipe();
			}

			if (extendedKeyBytes == null)
				extendedKeyBytes = HDKey.paddingToExtendedPrivateKey(keyBytes);

			storePrivateKey(did, id, extendedKeyBytes, storepass);
		} else {
			extendedKeyBytes = keyBytes;
		}

		return extendedKeyBytes;
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
		if (did == null)
			throw new IllegalArgumentException();

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
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		return containsPrivateKeys(_did);
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
	public boolean containsPrivateKey(DID did, DIDURL id)
			throws DIDStoreException {
		if (did == null || id == null)
			throw new IllegalArgumentException();

		return storage.containsPrivateKey(did, id);
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
	public boolean containsPrivateKey(String did, String id)
			throws DIDStoreException {
		DID _did = null;
		DIDURL _id = null;
		try {
			_did = new DID(did);
			_id = new DIDURL(_did, id);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		return containsPrivateKey(_did, _id);
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
	public boolean deletePrivateKey(DID did, DIDURL id) throws DIDStoreException {
		if (did == null || id == null)
			throw new IllegalArgumentException();

		return storage.deletePrivateKey(did, id);
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
	public boolean deletePrivateKey(String did, String id)
			throws DIDStoreException {
		DID _did = null;
		DIDURL _id = null;
		try {
			_did = new DID(did);
			_id = new DIDURL(_did, id);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		return deletePrivateKey(_did, _id);
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
	protected String sign(DID did, DIDURL id, String storepass, byte[] digest)
			throws DIDStoreException {
		if (did == null || storepass == null || storepass.isEmpty() || digest == null)
			throw new IllegalArgumentException();

		if (id == null) {
			DIDDocument doc = loadDid(did);
			if (doc == null)
				throw new DIDStoreException("Can not resolve DID document.");

			id = doc.getDefaultPublicKeyId();
		}

		HDKey key = HDKey.deserialize(loadPrivateKey(did, id, storepass));
		byte[] sig = EcdsaSigner.sign(key.getPrivateKeyBytes(), digest);
		key.wipe();

		return Base64.encodeToString(sig,
				Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
	}

	/**
	 * Sign the digest data by the specified key.
	 *
	 * @param did the owner of sign key
	 * @param storepass the password for DIDStore
	 * @param digest the digest data
	 * @return the signature string
	 * @throws DIDStoreException can not get DID Document if no specified sign key
	 */
	protected String sign(DID did, String storepass, byte[] digest)
			throws DIDStoreException {
		return sign(did, null, storepass, digest);
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
		ReEncryptor ree = new ReEncryptor() {
			@Override
			public String reEncrypt(String data) throws DIDStoreException {
				byte[] secret = DIDStore.decryptFromBase64(data, oldPassword);
				String result = DIDStore.encryptToBase64(secret, newPassword);
				Arrays.fill(secret, (byte)0);

				return result;
			}
		};

		storage.changePassword(ree);
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

				VerifiableCredential vc = storage.loadCredential(did, id);
				vc.setMetadata(storage.loadCredentialMetadata(did, id));
				de.addCredential(vc);
			}
		}

		if (storage.containsPrivateKeys(did)) {
			List<PublicKey> pks = doc.getPublicKeys();
			for (PublicKey pk : pks) {
				DIDURL id = pk.getId();
				if (storage.containsPrivateKey(did, id)) {
					log.debug("Exporting private key {}...", id.toString());

					String key = storage.loadPrivateKey(did, id);
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
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		exportDid(_did, out, password, storepass);
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
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		exportDid(_did, out, password, storepass);
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
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		exportDid(_did, file, password, storepass);
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
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		exportDid(_did, file, password, storepass);
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
				storage.storeCredentialMetadata(doc.getSubject(), vc.getId(), vc.getMetadata());
			}
		}

		List<DIDExport.PrivateKey> sks = de.getPrivatekey();
		if (sks != null) {
			for (DIDExport.PrivateKey sk : sks) {
				log.debug("Importing private key {}...", sk.getId().toString());
				storage.storePrivateKey(doc.getSubject(), sk.getId(),
						sk.getKey(password, storepass));
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
	static class PrivateIdentityExport extends DIDObject<PrivateIdentityExport> {
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
		protected PrivateIdentityExport(@JsonProperty(value = "type", required = true) String type) {
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

		public PrivateIdentityExport seal(String exportpass) {
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

	private PrivateIdentityExport exportPrivateIdentity(String password, String storepass)
			throws DIDStoreException {
		PrivateIdentityExport pie = new PrivateIdentityExport(DID_EXPORT);

		if (storage.containsMnemonic())
			pie.setMnemonic(storage.loadMnemonic(), storepass, password);

		pie.setKey(storage.loadPrivateIdentity(), storepass, password);

		if (storage.containsPublicIdentity())
			pie.setPubkey(storage.loadPublicIdentity());

		pie.setIndex(storage.loadPrivateIdentityIndex());
		return pie.seal(password);
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
	public void exportPrivateIdentity(OutputStream out, String password, String storepass)
			throws DIDStoreException, IOException {
		if (out == null || password == null || password.isEmpty() ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		try {
			exportPrivateIdentity(password, storepass).serialize(out);
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
	public void exportPrivateIdentity(Writer out, String password, String storepass)
			throws DIDStoreException, IOException {
		if (out == null || password == null || password.isEmpty()
				|| storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		try {
			exportPrivateIdentity(password, storepass).serialize(out);
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
	public void exportPrivateIdentity(File file, String password, String storepass)
			throws DIDStoreException, IOException {
		try {
			exportPrivateIdentity(password, storepass).serialize(file);
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
	public void exportPrivateIdentity(String file, String password, String storepass)
			throws DIDStoreException, IOException {
		if (file == null || file.isEmpty() || password == null ||
				password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		exportPrivateIdentity(new File(file), password, storepass);
	}

	private void importPrivateIdentity(PrivateIdentityExport pie, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		pie.verify(password);

		// Save
		String encryptedMnemonic = pie.getMnemonic(password, storepass);
		if (encryptedMnemonic != null)
			storage.storeMnemonic(encryptedMnemonic);

		storage.storePrivateIdentity(pie.getKey(password, storepass));

		String pubkey = pie.getPubkey();
		if (pubkey != null)
			storage.storePublicIdentity(pubkey);

		storage.storePrivateIdentityIndex(pie.getIndex());
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
	public void importPrivateIdentity(InputStream in, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException  {
		if (in == null || password == null || password.isEmpty() ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		PrivateIdentityExport pie;
		try {
			pie = PrivateIdentityExport.parse(in, PrivateIdentityExport.class);
		} catch (DIDSyntaxException e) {
			throw (MalformedExportDataException)e;
		}
		importPrivateIdentity(pie, password, storepass);
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
	public void importPrivateIdentity(Reader in, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		if (in == null || password == null || password.isEmpty() ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		PrivateIdentityExport pie;
		try {
			pie = PrivateIdentityExport.parse(in, PrivateIdentityExport.class);
		} catch (DIDSyntaxException e) {
			throw (MalformedExportDataException)e;
		}
		importPrivateIdentity(pie, password, storepass);
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
	public void importPrivateIdentity(File file, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		if (file == null || password == null || password.isEmpty() ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		PrivateIdentityExport pie;
		try {
			pie = PrivateIdentityExport.parse(file, PrivateIdentityExport.class);
		} catch (DIDSyntaxException e) {
			throw (MalformedExportDataException)e;
		}
		importPrivateIdentity(pie, password, storepass);
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
	public void importPrivateIdentity(String file, String password, String storepass)
			throws MalformedExportDataException, DIDStoreException, IOException {
		if (file == null || file.isEmpty() || password == null ||
				password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		importPrivateIdentity(new File(file), password, storepass);
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
		if (out == null || password == null || password.isEmpty()
				|| storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		ZipEntry ze;

		if (containsPrivateIdentity()) {
			ze = new ZipEntry("privateIdentity");
			out.putNextEntry(ze);
			exportPrivateIdentity(out, password, storepass);
			out.closeEntry();
		}

		List<DID> dids = listDids(DID_ALL);
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
		if (zipFile == null || password == null || password.isEmpty()
				|| storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

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
		if (zipFile == null || zipFile.isEmpty() || password == null
				|| password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

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
		if (in == null || password == null || password.isEmpty()
				|| storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		ZipEntry ze;
		while ((ze = in.getNextEntry()) != null) {
			if (ze.getName().equals("privateIdentity"))
				importPrivateIdentity(in, password, storepass);
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
		if (zipFile == null || password == null || password.isEmpty()
				|| storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

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
		if (zipFile == null || zipFile.isEmpty() || password == null
				|| password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		importStore(new File(zipFile), password, storepass);
	}
}
