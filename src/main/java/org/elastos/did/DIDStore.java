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
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
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
import org.elastos.did.exception.DIDDeactivatedException;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDExpiredException;
import org.elastos.did.exception.DIDNotFoundException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.MalformedCredentialException;
import org.elastos.did.exception.MalformedDIDException;
import org.elastos.did.exception.MalformedDocumentException;
import org.elastos.did.exception.WrongPasswordException;
import org.elastos.did.metadata.CredentialMetadataImpl;
import org.elastos.did.metadata.DIDMetadataImpl;
import org.elastos.did.util.JsonHelper;
import org.elastos.did.util.LRUCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.digests.SHA256Digest;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public final class DIDStore {
	private static final int CACHE_INITIAL_CAPACITY = 16;
	private static final int CACHE_MAX_CAPACITY = 32;

	public static final int DID_HAS_PRIVATEKEY = 0;
	public static final int DID_NO_PRIVATEKEY = 1;
	public static final int DID_ALL	= 2;

	private static final String DID_EXPORT = "did.elastos.export/1.0";

	private Map<DID, DIDDocument> didCache;
	private Map<DIDURL, VerifiableCredential> vcCache;

	private DIDStorage storage;
	private DIDBackend backend;

	private static final Logger log = LoggerFactory.getLogger(DIDStore.class);

	public interface ConflictHandle {
		/**
	     * The function indicate how to resolve the confict, if the local document is different
         * with the one resolved from chain.
		 *
		 * @param chainCopy the document from chain
		 * @param localCopy the document from local device
		 * @return
		 */
		DIDDocument merge(DIDDocument chainCopy, DIDDocument localCopy);
	}

	private DIDStore(int initialCacheCapacity, int maxCacheCapacity,
			DIDAdapter adapter, DIDStorage storage) {
		if (maxCacheCapacity > 0) {
			this.didCache = LRUCache.createInstance(initialCacheCapacity, maxCacheCapacity);
			this.vcCache = LRUCache.createInstance(initialCacheCapacity, maxCacheCapacity);
		}

		this.backend = DIDBackend.getInstance(adapter);
		this.storage = storage;
	}

	/**
	 * Initialize or check the DIDStore.
	 *
	 * @param type the type for different file system
	 * @param location the location of DIDStore
	 * @param initialCacheCapacity the initial capacity for cache
	 * @param maxCacheCapacity the max capacity for cache
	 * @param adapter the DIDAdaper object
	 * @return the DIDStore object
	 * @throws DIDStoreException Unsupport the specified store type.
	 */
	public static DIDStore open(String type, String location,
			int initialCacheCapacity, int maxCacheCapacity,
			DIDAdapter adapter) throws DIDStoreException {
		if (type == null || location == null || location.isEmpty() ||
				maxCacheCapacity < initialCacheCapacity || adapter == null)
			throw new IllegalArgumentException();

		if (!type.equals("filesystem"))
			throw new DIDStoreException("Unsupported store type: " + type);

		DIDStorage storage = new FileSystemStorage(location);
		return new DIDStore(initialCacheCapacity, maxCacheCapacity,
				adapter, storage);
	}

	/**
	 * Initialize or check the DIDStore.
	 *
	 * @param type the type for different file system
	 * @param location the location of DIDStore
	 * @param adapter the DIDAdaper object
	 * @return the DIDStore object
	 * @throws DIDStoreException Unsupport the specified store type.
	 */
	public static DIDStore open(String type, String location, DIDAdapter adapter)
			throws DIDStoreException {
		return open(type, location, CACHE_INITIAL_CAPACITY,
				CACHE_MAX_CAPACITY, adapter);
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
	 * @throws DIDStoreException
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
					try {
						chainCopy = DIDBackend.resolve(did, true);
					} catch (DIDExpiredException | DIDDeactivatedException e) {
						log.debug("{} is {}, skip.", did.toString(),
								e instanceof DIDExpiredException ?
								"expired" : "deactivated");
						blanks = 0;
						continue;
					}

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
						storePrivateKey(did, finalCopy.getDefaultPublicKey(),
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
			l.getMetadataImpl().setPublished(c.getMetadata().getPublished());
			l.getMetadataImpl().setSignature(c.getMetadata().getSignature());
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
			doc = db.seal(storepass);
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

	/**
	 * Publish DID content(DIDDocument) to chain.
	 *
	 * @param did the DID which to be published into chain
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
	public void publishDid(DID did, DIDURL signKey, boolean force, String storepass)
			throws DIDBackendException, DIDStoreException, InvalidKeyException {
		if (did == null || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		log.info("Publishing {}{}...", did.toString(),
				force ? " in force mode" : "");

		DIDDocument doc = loadDid(did);
		if (doc == null) {
			log.error("No document for {}", did.toString());
			throw new DIDStoreException("Can not find the document for " + did);
		}

		if (!doc.isGenuine()) {
			log.error("{} is not genuine.", did.toString());
			throw new DIDStoreException("DID document is not genuine.");
		}

		if (doc.isDeactivated()) {
			log.error("{} already deactivated.", did.toString());
			throw new DIDStoreException("DID already deactivated.");
		}

		if (doc.isExpired() && !force) {
			log.error("{} already expired, use force mode to publish anyway.", did.toString());
			throw new DIDStoreException("DID already expired.");
		}

		String lastTxid = null;
		String reolvedSignautre = null;
		DIDDocument resolvedDoc = did.resolve(true);
		if (resolvedDoc != null) {
			if (resolvedDoc.isDeactivated()) {
				doc.getMetadataImpl().setDeactivated(true);
				storage.storeDidMetadata(doc.getSubject(), doc.getMetadataImpl());

				log.error("{} already deactivated.", did.toString());
				throw new DIDStoreException("DID already deactivated.");
			}

			reolvedSignautre = resolvedDoc.getProof().getSignature();

			if (!force) {
				String localPrevSignature = doc.getMetadata().getPreviousSignature();
				String localSignature = doc.getMetadata().getSignature();

				if (localPrevSignature == null && localSignature == null) {
					log.error("Missing signatures information, " +
							"DID SDK dosen't know how to handle it, " +
							"use force mode to ignore checks.");
					throw new DIDStoreException("DID document not up-to-date");
				} else if (localPrevSignature == null || localSignature == null) {
					String ls = localPrevSignature != null ? localPrevSignature : localSignature;
					if (!ls.equals(reolvedSignautre)) {
						log.error("Current copy not based on the lastest on-chain copy, signature mismatch.");
						throw new DIDStoreException("DID document not up-to-date");
					}
				} else {
					if (!localSignature.equals(reolvedSignautre) &&
						!localPrevSignature.equals(reolvedSignautre)) {
						log.error("Current copy not based on the lastest on-chain copy, signature mismatch.");
						throw new DIDStoreException("DID document not up-to-date");
					}
				}
			}

			lastTxid = resolvedDoc.getMetadata().getTransactionId();
		}

		if (signKey == null)
			signKey = doc.getDefaultPublicKey();

		if (lastTxid == null || lastTxid.isEmpty()) {
			log.info("Try to publish[create] {}...", did.toString());
			backend.create(doc, signKey, storepass);
		} else {
			log.info("Try to publish[update] {}...", did.toString());
			backend.update(doc, lastTxid, signKey, storepass);
		}

		doc.getMetadataImpl().setPreviousSignature(reolvedSignautre);
		doc.getMetadataImpl().setSignature(doc.getProof().getSignature());
		storage.storeDidMetadata(doc.getSubject(), doc.getMetadataImpl());
	}

	/**
	 * Publish DID content(DIDDocument) to chain without force mode.
	 *
	 * @param did the DID which to be published into chain
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException publish did failed because of DIDBackend error.
	 * @throws DIDStoreException there is no activated DID or no lastest DID Document in DIDStore.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public void publishDid(DID did, DIDURL signKey, String storepass)
			throws DIDBackendException, DIDStoreException, InvalidKeyException {
		publishDid(did, signKey, false, storepass);
	}

	/**
	 * Publish DID content(DIDDocument) to chain.
	 *
	 * @param did the DID string which to be published into chain
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
	public void publishDid(String did, String signKey, boolean force, String storepass)
			throws DIDBackendException, DIDStoreException, InvalidKeyException {
		DID _did = null;
		DIDURL _signKey = null;

		try {
			_did = new DID(did);
			_signKey = signKey == null ? null : new DIDURL(_did, signKey);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		publishDid(_did, _signKey, force, storepass);
	}

	/**
	 * Publish DID content(DIDDocument) to chain without force mode.
	 *
	 * @param did the DID string which to be published into chain
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException publish did failed because of DIDBackend error.
	 * @throws DIDStoreException there is no activated DID or no lastest DID Document in DIDStore.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public void publishDid(String did, String signKey, String storepass)
			throws DIDBackendException, DIDStoreException, InvalidKeyException {
		publishDid(did, signKey, false, storepass);
	}

	/**
	 * Publish DID content(DIDDocument) to chain without force mode.
	 * Specify the default key to sign.
	 *
	 * @param did the DID which to be published into chain
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException publish did failed because of DIDBackend error.
	 * @throws DIDStoreException there is no activated DID or no lastest DID Document in DIDStore.
	 */
	public void publishDid(DID did, String storepass)
			throws DIDBackendException, DIDStoreException {
		try {
			publishDid(did, null, storepass);
		} catch (InvalidKeyException ignore) {
			// Dead code.
		}
	}

	/**
	 * Publish DID content(DIDDocument) to chain without force mode.
	 * Specify the default key to sign.
	 *
	 * @param did the DID string which to be published into chain
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException publish did failed because of DIDBackend error.
	 * @throws DIDStoreException there is no activated DID or no lastest DID Document in DIDStore.
	 */
	public void publishDid(String did, String storepass)
			throws DIDBackendException, DIDStoreException {
		try {
			publishDid(did, null, storepass);
		} catch (InvalidKeyException ignore) {
			// Dead code.
		}
	}

	/**
	 * Publish DID content(DIDDocument) to chain with asynchronous mode.
	 *
	 * @param did the DID which to be published into chain
	 * @param signKey the key to sign
	 * @param force force = true, must be publish whether the local document is lastest one or not;
	 *              force = false, must not be publish if the local document is not the lastest one,
	 *              and must resolve at first.
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> publishDidAsync(DID did,
			DIDURL signKey, boolean force, String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				publishDid(did, signKey, force, storepass);
			} catch (DIDBackendException | DIDStoreException | InvalidKeyException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Publish DID content(DIDDocument) to chain with asynchronous mode.
	 *
	 * @param did the DID string which to be published into chain
	 * @param signKey the key to sign
	 * @param force force = true, must be publish whether the local document is lastest one or not;
	 *              force = false, must not be publish if the local document is not the lastest one,
	 *              and must resolve at first.
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> publishDidAsync(String did,
			String signKey, boolean force, String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				publishDid(did, signKey, force, storepass);
			} catch (DIDBackendException | DIDStoreException | InvalidKeyException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Publish DID content(DIDDocument) to chain with asynchronous mode.
	 * Also this method is defined without force mode.
	 *
	 * @param did the DID string which to be published into chain
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> publishDidAsync(DID did,
			DIDURL signKey, String storepass) {
		return publishDidAsync(did, signKey, false, storepass);
	}

	/**
	 * Publish DID content(DIDDocument) to chain with asynchronous mode.
	 * Also this method is defined without force mode.
	 *
	 * @param did the DID string which to be published into chain
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> publishDidAsync(String did,
			String signKey, String storepass) {
		return publishDidAsync(did, signKey, false, storepass);
	}

	/**
	 * Publish DID content(DIDDocument) to chain with asynchronous mode.
	 * Also this method is defined without force mode and specify the default key to sign.
	 *
	 * @param did the DID which to be published into chain
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> publishDidAsync(DID did, String storepass) {
		return publishDidAsync(did, null, storepass);
	}

	/**
	 * Publish DID content(DIDDocument) to chain with asynchronous mode.
	 * Also this method is defined without force mode and specify the default key to sign.
	 *
	 * @param did the DID string which to be published into chain
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> publishDidAsync(String did,
			String storepass) {
		return publishDidAsync(did, null, storepass);
	}

	/**
	 * Deactivate self use authentication key.
	 *
	 * @param did the DID to be activated
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException deactivate did failed because of did backend error.
	 * @throws DIDStoreException deactivate did failed because of did store error.
	 * @throws InvalidKeyException there is no an authenication key.
	 */
	public void deactivateDid(DID did, DIDURL signKey, String storepass)
			throws DIDBackendException, DIDStoreException, InvalidKeyException {
		if (did == null || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		// Document should use the IDChain's copy
		boolean localCopy = false;
		DIDDocument doc = DIDBackend.resolve(did);
		if (doc == null) {
			// Fail-back: try to load document from local store
			doc = loadDid(did);
			if (doc == null)
				throw new DIDNotFoundException(did.toString());
			else
				localCopy = true;
		} else {
			doc.getMetadataImpl().setStore(this);
		}

		if (signKey == null) {
			signKey = doc.getDefaultPublicKey();
		} else {
			if (!doc.isAuthenticationKey(signKey))
				throw new InvalidKeyException("Not an authentication key.");
		}

		backend.deactivate(doc, signKey, storepass);

		// Save deactivated status to DID metadata
		if (localCopy) {
			doc.getMetadataImpl().setDeactivated(true);
			storage.storeDidMetadata(did, doc.getMetadataImpl());
		}
	}

	/**
	 * Deactivate self use authentication key.
	 *
	 * @param did the DID string to be activated
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException deactivate did failed because of did backend error.
	 * @throws DIDStoreException deactivate did failed because of did store error.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public void deactivateDid(String did, String signKey, String storepass)
			throws DIDBackendException, DIDStoreException, InvalidKeyException {
		DID _did = null;
		DIDURL _signKey = null;
		try {
			_did = new DID(did);
			_signKey = signKey == null ? null : new DIDURL(_did, signKey);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		deactivateDid(_did, _signKey, storepass);
	}

	/**
	 * Deactivate self use authentication key.
	 * Specify the default key to sign.
	 *
	 * @param did the DID to be activated
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException deactivate did failed because of did backend error.
	 * @throws DIDStoreException deactivate did failed because of did store error.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public void deactivateDid(DID did, String storepass)
			throws DIDBackendException, DIDStoreException {
		try {
			deactivateDid(did, (DIDURL)null, storepass);
		} catch (InvalidKeyException ignore) {
			// Dead code.
		}
	}

	/**
	 * Deactivate self use authentication key.
	 * Specify the default key to sign.
	 *
	 * @param did the DID string to be activated
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException deactivate did failed because of did backend error.
	 * @throws DIDStoreException deactivate did failed because of did store error.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public void deactivateDid(String did, String storepass)
			throws DIDBackendException, DIDStoreException {
		try {
			deactivateDid(did, null, storepass);
		} catch (InvalidKeyException ignore) {
			// Dead code.
		}
	}

	/**
	 * Deactivate self use authentication key with asynchronous mode.
	 *
	 * @param did the DID to be activated
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> deactivateDidAsync(DID did,
			DIDURL signKey, String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				deactivateDid(did, signKey, storepass);
			} catch (DIDBackendException | DIDStoreException | InvalidKeyException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Deactivate self use authentication key with asynchronous mode.
	 *
	 * @param did the DID string to be activated
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> deactivateDidAsync(String did,
			String signKey, String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				deactivateDid(did, signKey, storepass);
			} catch (DIDBackendException | DIDStoreException | InvalidKeyException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Deactivate self use authentication key with asynchronous mode.
	 * Specify the default key to sign.
	 *
	 * @param did the DID to be activated
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> deactivateDidAsync(DID did, String storepass) {
		return deactivateDidAsync(did, (DIDURL)null, storepass);
	}

	/**
	 * Deactivate self use authentication key with asynchronous mode.
	 * Specify the default key to sign.
	 *
	 * @param did the DID to be activated
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> deactivateDidAsync(String did, String storepass) {
		return deactivateDidAsync(did, null, storepass);
	}

	/**
	 * Deactivate target DID by authorizor's DID.
	 *
	 * @param target the target DID
	 * @param did the authorizor's DID
	 * @param signKey the authorizor's key to sign
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException deactivate did failed because of did backend error.
	 * @throws DIDStoreException deactivate did failed because of did store error.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public void deactivateDid(DID target, DID did, DIDURL signKey, String storepass)
			throws DIDBackendException, DIDStoreException, InvalidKeyException {
		if (target == null || did == null ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		// All documents should use the IDChain's copy
		DIDDocument doc = DIDBackend.resolve(did);
		if (doc == null) {
			// Fail-back: try to load document from local store
			doc = loadDid(did);
			if (doc == null)
				throw new DIDNotFoundException(did.toString());
		} else {
			doc.getMetadataImpl().setStore(this);
		}

		PublicKey signPk = null;
		if (signKey != null) {
			signPk = doc.getAuthenticationKey(signKey);
			if (signPk == null)
				throw new InvalidKeyException("Not an authentication key.");
		}

		DIDDocument targetDoc = DIDBackend.resolve(target);
		if (targetDoc == null)
			throw new DIDNotFoundException(target.toString());

		if (targetDoc.getAuthorizationKeyCount() == 0)
			throw new InvalidKeyException("No matched authorization key.");

		// The authorization key id in the target doc
		DIDURL targetSignKey = null;

		List<PublicKey> authorizationKeys = targetDoc.getAuthorizationKeys();
		matchloop: for (PublicKey targetPk : authorizationKeys) {
			if (!targetPk.getController().equals(did))
				continue;

			if (signPk != null) {
				if (!targetPk.getPublicKeyBase58().equals(signPk.getPublicKeyBase58()))
					continue;

				targetSignKey = targetPk.getId();
				break;
			} else {
				List<PublicKey> pks = doc.getAuthenticationKeys();
				for (PublicKey pk : pks) {
					if (pk.getPublicKeyBase58().equals(targetPk.getPublicKeyBase58())) {
						signPk = pk;
						signKey = signPk.getId();
						targetSignKey = targetPk.getId();
						break matchloop;
					}
				}
			}
		}

		if (targetSignKey == null)
			throw new InvalidKeyException("No matched authorization key.");

		backend.deactivate(target, targetSignKey, doc, signKey, storepass);
	}

	/**
	 * Deactivate target DID by authorizor's DID.
	 *
	 * @param target the target DID string
	 * @param did the authorizor's DID
	 * @param signKey the authorizor's key to sign
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException deactivate did failed because of did backend error.
	 * @throws DIDStoreException deactivate did failed because of did store error.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public void deactivateDid(String target, String did,
			String signKey, String storepass)
			throws DIDBackendException, DIDStoreException, InvalidKeyException {
		DID _target = null;
		DID _did = null;
		DIDURL _signKey = null;
		try {
			_target = new DID(target);
			_did = new DID(did);
			_signKey = signKey == null ? null : new DIDURL(_did, signKey);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		deactivateDid(_target, _did, _signKey, storepass);
	}

	/**
	 * Deactivate target DID by authorizor's DID.
	 *
	 * @param target the target DID string
	 * @param did the authorizor's DID, use the default key to sign.
	 * @param storepass the password for DIDStore
	 * @throws DIDBackendException deactivate did failed because of did backend error.
	 * @throws DIDStoreException deactivate did failed because of did store error.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public void deactivateDid(DID target, DID did, String storepass)
			throws DIDBackendException, DIDStoreException, InvalidKeyException {
		deactivateDid(target, did, null, storepass);
	}

	/*
	public void deactivateDid(String target, String did, String storepass)
			throws DIDBackendException, DIDStoreException, InvalidKeyException {
		deactivateDid(target, did, null, storepass);
	}
	*/

	/**
	 * Deactivate target DID by authorizor's DID with asynchronous mode.
	 *
	 * @param target the target DID
	 * @param did the authorizor's DID.
	 * @param signKey the authorizor's key to sign
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> deactivateDidAsync(DID target, DID did,
			DIDURL signKey, String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				deactivateDid(target, did, signKey, storepass);
			} catch (DIDBackendException | DIDStoreException | InvalidKeyException e) {
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
	 * @param confirms
	 * @param signKey the authorizor's key to sign
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> deactivateDidAsync(String target,
			String did, int confirms, String signKey, String storepass) {
		CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
			try {
				deactivateDid(target, did, signKey, storepass);
			} catch (DIDBackendException | DIDStoreException | InvalidKeyException e) {
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
	 * @param confirms
	 * @param signKey the authorizor's key to sign
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> deactivateDidAsync(String target,
			String did, String signKey, String storepass) {
		return deactivateDidAsync(target, did, signKey, storepass);
	}

	/**
	 * Deactivate target DID by authorizor's DID with asynchronous mode.
	 *
	 * @param target the target DID
	 * @param did the authorizor's DID, use the default key to sign.
	 * @param storepass the password for DIDStore
	 * @return the new CompletableStage, no result.
	 */
	public CompletableFuture<Void> deactivateDidAsync(DID target, DID did,
			String storepass) {
		return deactivateDidAsync(target, did, null, storepass);
	}

	/*
	public CompletableFuture<Void> deactivateDidAsync(String target,
			String did, String storepass) {
		return deactivateDidAsync(target, did, confirms, null, storepass);
	}
	*/

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

		DIDMetadataImpl metadata = loadDidMetadata(doc.getSubject());
		doc.getMetadataImpl().merge(metadata);
		doc.getMetadataImpl().setStore(this);

		storage.storeDidMetadata(doc.getSubject(), doc.getMetadataImpl());

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
	protected void storeDidMetadata(DID did, DIDMetadataImpl metadata)
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
	protected void storeDidMetadata(String did, DIDMetadataImpl metadata)
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
	protected DIDMetadataImpl loadDidMetadata(DID did) throws DIDStoreException {
		if (did == null)
			throw new IllegalArgumentException();

		DIDMetadataImpl metadata = null;
		DIDDocument doc = null;

		if (didCache != null) {
			doc = didCache.get(did);
			if (doc != null) {
				metadata = doc.getMetadataImpl();
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
	protected DIDMetadataImpl loadDidMetadata(String did) throws DIDStoreException {
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
			DIDMetadataImpl metadata = storage.loadDidMetadata(did);
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
			DIDMetadataImpl metadata = loadDidMetadata(did);
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

		CredentialMetadataImpl metadata = loadCredentialMetadata(
				credential.getSubject().getId(), credential.getId());
		credential.getMetadataImpl().merge(metadata);
		credential.getMetadataImpl().setStore(this);

		storage.storeCredentialMetadata(credential.getSubject().getId(),
				credential.getId(), credential.getMetadataImpl());

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
			CredentialMetadataImpl metadata) throws DIDStoreException {
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
			CredentialMetadataImpl metadata) throws DIDStoreException {
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
	protected CredentialMetadataImpl loadCredentialMetadata(DID did, DIDURL id)
			throws DIDStoreException {
		if (did == null || id == null)
			throw new IllegalArgumentException();

		CredentialMetadataImpl metadata = null;
		VerifiableCredential vc = null;

		if (vcCache != null) {
			vc = vcCache.get(id);
			if (vc != null) {
				metadata = vc.getMetadataImpl();
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
	protected CredentialMetadataImpl loadCredentialMetadata(String did, String id)
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
			CredentialMetadataImpl metadata = storage.loadCredentialMetadata(did, id);
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
			CredentialMetadataImpl metadata = loadCredentialMetadata(did, id);
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

			id = doc.getDefaultPublicKey();
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
	 * @param id the identifier of sign key
	 * @param storepass the password for DIDStore
	 * @param digest the digest data
	 * @return the signature string
	 * @throws DIDStoreException can not get DID Document if no specified sign key.
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

	private void exportDid(DID did, JsonGenerator generator, String password,
			String storepass) throws DIDStoreException, IOException {
		// All objects should load directly from storage,
		// avoid affects the cached objects.

		DIDDocument doc = storage.loadDid(did);
		if (doc == null)
			throw new DIDStoreException("Export DID " + did + " failed, not exist.");

		log.debug("Exporting {}...", did.toString());

		SHA256Digest sha256 = new SHA256Digest();
		byte[] bytes = password.getBytes();
		sha256.update(bytes, 0, bytes.length);

		generator.writeStartObject();

		// Type
		generator.writeStringField("type", DID_EXPORT);
		bytes = DID_EXPORT.getBytes();
		sha256.update(bytes, 0, bytes.length);

		// DID
		String value = did.toString();
		generator.writeStringField("id", value);
		bytes = value.getBytes();
		sha256.update(bytes, 0, bytes.length);

		// Create
		Date now = Calendar.getInstance(Constants.UTC).getTime();
		value = JsonHelper.formatDate(now);
		generator.writeStringField("created", value);
		bytes = value.getBytes();
		sha256.update(bytes, 0, bytes.length);

		// Document
		generator.writeFieldName("document");
		generator.writeStartObject();

		generator.writeFieldName("content");
		doc.toJson(generator, false);
		value = doc.toString(true);
		bytes = value.getBytes();
		sha256.update(bytes, 0, bytes.length);

		DIDMetadataImpl didMetadata = storage.loadDidMetadata(did);
		if (!didMetadata.isEmpty()) {
			generator.writeFieldName("metadata");
			value = didMetadata.toString();
			generator.writeRawValue(value);
			bytes = value.getBytes();
			sha256.update(bytes, 0, bytes.length);
		}

		generator.writeEndObject();

		// Credential
		if (storage.containsCredentials(did)) {
			generator.writeFieldName("credential");
			generator.writeStartArray();

			List<DIDURL> ids = listCredentials(did);
			Collections.sort(ids);
			for (DIDURL id : ids) {
				log.debug("Exporting credential {}...", id.toString());

				generator.writeStartObject();

				generator.writeFieldName("content");
				VerifiableCredential vc = storage.loadCredential(did, id);
				vc.toJson(generator, false);
				value = vc.toString(true);
				bytes = value.getBytes();
				sha256.update(bytes, 0, bytes.length);

				CredentialMetadataImpl metadata = storage.loadCredentialMetadata(did, id);
				if (!metadata.isEmpty()) {
					generator.writeFieldName("metadata");
					value = metadata.toString();
					generator.writeRawValue(value);
					bytes = value.getBytes();
					sha256.update(bytes, 0, bytes.length);
				}

				generator.writeEndObject();
			}

			generator.writeEndArray();
		}

		// Private key
		if (storage.containsPrivateKeys(did)) {
			generator.writeFieldName("privatekey");
			generator.writeStartArray();

			List<PublicKey> pks = doc.getPublicKeys();
			for (PublicKey pk : pks) {
				DIDURL id = pk.getId();

				if (storage.containsPrivateKey(did, id)) {
					log.debug("Exporting private key {}...", id.toString());

					String csk = storage.loadPrivateKey(did, id);
					byte[] sk = decryptFromBase64(csk, storepass);
					csk = encryptToBase64(sk, password);
					Arrays.fill(sk, (byte)0);

					generator.writeStartObject();

					value = id.toString();
					generator.writeStringField("id", value);
					bytes = value.getBytes();
					sha256.update(bytes, 0, bytes.length);

					generator.writeStringField("key", csk);
					bytes = csk.getBytes();
					sha256.update(bytes, 0, bytes.length);

					generator.writeEndObject();
				}
			}

			generator.writeEndArray();
		}

		// Fingerprint
		byte digest[] = new byte[32];
		sha256.doFinal(digest, 0);
		String fingerprint = Base64.encodeToString(digest,
				Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
		generator.writeStringField("fingerprint", fingerprint);

		generator.writeEndObject();
	}

	/**
     * Export DID information into file with json format. The json content include document,
     * credentials, private keys and meta.
	 *
	 * @param did the specified DID
	 * @param out the export output
	 * @param password the password to encrypt the private key in output.
	 * @param storepass the password for DIDStore.
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void exportDid(DID did, OutputStream out, String password,
			String storepass) throws DIDStoreException, IOException {
		if (did == null || out == null || password == null ||
				password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		JsonFactory factory = new JsonFactory();
		JsonGenerator generator = factory.createGenerator(out);
		generator.configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false);
		exportDid(did, generator, password, storepass);
		generator.close();
	}

	/**
     * Export DID information into file with json format. The json content include document,
     * credentials, private keys and meta.
	 *
	 * @param did the specified DID
	 * @param out the export output
	 * @param password the password to encrypt the private key in output.
	 * @param storepass the password for DIDStore.
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
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
     * Export DID information into file with json format. The json content include document,
     * credentials, private keys and meta.
	 *
	 * @param did the specified DID
	 * @param out the export output
	 * @param password the password to encrypt the private key in output.
	 * @param storepass the password for DIDStore.
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void exportDid(DID did, Writer out, String password,
			String storepass) throws DIDStoreException, IOException {
		if (did == null || out == null || password == null ||
				password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		JsonFactory factory = new JsonFactory();
		JsonGenerator generator = factory.createGenerator(out);
		generator.configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false);
		exportDid(did, generator, password, storepass);
		generator.close();
	}

	/**
     * Export DID information into file with json format. The json content include document,
     * credentials, private keys and meta.
	 *
	 * @param did the specified DID string
	 * @param out the export output
	 * @param password the password to encrypt the private key in output.
	 * @param storepass the password for DIDStore.
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void exportDid(String did, Writer out, String password,
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
     * Export DID information into file with json format. The json content include document,
     * credentials, private keys and meta.
	 *
	 * @param did the specified DID
	 * @param file the export output
	 * @param password the password to encrypt the private key in output.
	 * @param storepass the password for DIDStore.
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void exportDid(DID did, File file, String password,
			String storepass) throws DIDStoreException, IOException {
		if (did == null || file == null || password == null ||
				password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		exportDid(did, new FileWriter(file), password, storepass);
	}

	/**
     * Export DID information into file with json format. The json content include document,
     * credentials, private keys and meta.
	 *
	 * @param did the specified DID string
	 * @param file the export output
	 * @param password the password to encrypt the private key in output.
	 * @param storepass the password for DIDStore.
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void exportDid(String did, File file, String password,
			String storepass) throws DIDStoreException, IOException {
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		exportDid(_did, file, password, storepass);
	}

	/**
     * Export DID information into file with json format. The json content include document,
     * credentials, private keys and meta.
	 *
	 * @param did the specified DID
	 * @param file the export output
	 * @param password the password to encrypt the private key in output.
	 * @param storepass the password for DIDStore.
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void exportDid(DID did, String file, String password,
			String storepass) throws DIDStoreException, IOException {
		if (did == null || file == null || file.isEmpty() || password == null ||
				password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		exportDid(did, new File(file), password, storepass);
	}

	/**
     * Export DID information into file with json format. The json content include document,
     * credentials, private keys and meta.
	 *
	 * @param did the specified DID string
	 * @param out the export output
	 * @param password the password to encrypt the private key in output.
	 * @param storepass the password for DIDStore.
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void exportDid(String did, String file, String password,
			String storepass) throws DIDStoreException, IOException {
		DID _did = null;
		try {
			_did = new DID(did);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}

		exportDid(_did, file, password, storepass);
	}

	private void importDid(JsonNode root, String password, String storepass)
			throws DIDStoreException, IOException {
		Class<DIDStoreException> exceptionClass = DIDStoreException.class;

		SHA256Digest sha256 = new SHA256Digest();
		byte[] bytes = password.getBytes();
		sha256.update(bytes, 0, bytes.length);

		// Type
		String type = JsonHelper.getString(root, "type", false, null,
				"export type", exceptionClass);
		if (!type.equals(DID_EXPORT))
			throw new DIDStoreException("Invalid export data, unknown type.");
		bytes = type.getBytes();
		sha256.update(bytes, 0, bytes.length);

		// DID
		DID did = JsonHelper.getDid(root, "id", false, null,
				"DID subject", exceptionClass);
		bytes = did.toString().getBytes();
		sha256.update(bytes, 0, bytes.length);

		log.debug("Importing {}...", did.toString());

		// Created
		Date created = JsonHelper.getDate(root, "created", true, null,
				"export date", exceptionClass);
		bytes = JsonHelper.formatDate(created).getBytes();
		sha256.update(bytes, 0, bytes.length);

		// Document
		JsonNode node = root.get("document");
		if (node == null) {
			log.error("Missing DID document.");
			throw new DIDStoreException("Missing DID document in the export data");
		}

		JsonNode docNode = node.get("content");
		if (docNode == null) {
			log.error("Missing DID document content.");
			throw new DIDStoreException("Missing DID document content in the export data");
		}

		DIDDocument doc = null;
		try {
			doc = DIDDocument.fromJson(docNode);
		} catch (MalformedDocumentException e) {
			log.error("Parse DID document error.", e);
			throw new DIDStoreException("Invalid export data.", e);
		}

		if (!doc.getSubject().equals(did) || !doc.isGenuine()) {
			log.error("DID Document not blongs to {}", did.toString());
			throw new DIDStoreException("Invalid DID document in the export data.");
		}

		bytes = doc.toString(true).getBytes();
		sha256.update(bytes, 0, bytes.length);

		JsonNode metaNode = node.get("metadata");
		if (metaNode != null) {
			DIDMetadataImpl metadata = new DIDMetadataImpl();
			metadata.load(metaNode);
			metadata.setStore(this);
			doc.setMetadata(metadata);

			bytes = metadata.toString().getBytes();
			sha256.update(bytes, 0, bytes.length);
		}

		// Credential
		HashMap<DIDURL, VerifiableCredential> vcs = null;
		node = root.get("credential");
		if (node != null) {
			if (!node.isArray()) {
				log.error("Credential should be an array.");
				throw new DIDStoreException("Invalid export data, wrong credential data.");
			}

			vcs = new HashMap<DIDURL, VerifiableCredential>(node.size());

			for (int i = 0; i < node.size(); i++) {
				JsonNode vcNode = node.get(i).get("content");
				if (vcNode == null) {
					log.error("Missing credential " + i + " content");
					throw new DIDStoreException("Invalid export data.");
				}

				VerifiableCredential vc = null;

				try {
					vc = VerifiableCredential.fromJson(vcNode, did);
				} catch (MalformedCredentialException e) {
					log.error("Parse credential " + i + " error", e);
					throw new DIDStoreException("Invalid export data.", e);
				}

				if (!vc.getSubject().getId().equals(did) /* || !vc.isGenuine() */) {
					log.error("Credential {} not blongs to {}", i, did.toString());
					throw new DIDStoreException("Invalid credential in the export data.");
				}

				bytes = vc.toString(true).getBytes();
				sha256.update(bytes, 0, bytes.length);

				metaNode = node.get(i).get("metadata");
				if (metaNode != null) {
					CredentialMetadataImpl metadata = new CredentialMetadataImpl();
					metadata.load(metaNode);
					metadata.setStore(this);
					vc.setMetadata(metadata);

					bytes = metadata.toString().getBytes();
					sha256.update(bytes, 0, bytes.length);
				}

				vcs.put(vc.getId(), vc);
			}
		}

		// Private key
		HashMap<DIDURL, String> sks = null;
		node = root.get("privatekey");
		if (node != null) {
			if (!node.isArray()) {
				log.error("Privatekey should be an array.");
				throw new DIDStoreException("Invalid export data, wrong privatekey data.");
			}

			sks = new HashMap<DIDURL, String>(node.size());

			for (int i = 0; i < node.size(); i++) {
				DIDURL id = JsonHelper.getDidUrl(node.get(i), "id", did,
						"privatekey id", exceptionClass);
				String csk = JsonHelper.getString(node.get(i), "key", false, null,
						"privatekey", exceptionClass);

				bytes = id.toString().getBytes();
				sha256.update(bytes, 0, bytes.length);

				bytes = csk.getBytes();
				sha256.update(bytes, 0, bytes.length);

				byte[] sk = decryptFromBase64(csk, password);
				csk = encryptToBase64(sk, storepass);
				Arrays.fill(sk, (byte)0);

				sks.put(id, csk);
			}
		}

		// Fingerprint
		node = root.get("fingerprint");
		if (node == null) {
			log.error("Missing fingerprint");
			throw new DIDStoreException("Missing fingerprint in the export data");
		}
		String refFingerprint = node.asText();

		byte digest[] = new byte[32];
		sha256.doFinal(digest, 0);
		String fingerprint = Base64.encodeToString(digest,
				Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);

		if (!fingerprint.equals(refFingerprint)) {
			log.error("Fingerprint mismatch.");
			throw new DIDStoreException("Invalid export data, the fingerprint mismatch.");
		}

		// Save
		//
		// All objects should load directly from storage,
		// avoid affects the cached objects.
		log.debug("Importing document...");
		storage.storeDid(doc);
		storage.storeDidMetadata(doc.getSubject(), doc.getMetadataImpl());

		for (VerifiableCredential vc : vcs.values()) {
			log.debug("Importing credential {}...", vc.getId().toString());
			storage.storeCredential(vc);
			storage.storeCredentialMetadata(did, vc.getId(), vc.getMetadataImpl());
		}

		for (Map.Entry<DIDURL, String> sk : sks.entrySet()) {
			log.debug("Importing private key {}...", sk.getKey().toString());
			storage.storePrivateKey(did, sk.getKey(), sk.getValue());
		}
	}

	/**
	 * Import DID information by input.
	 *
	 * @param in the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void importDid(InputStream in, String password, String storepass)
			throws DIDStoreException, IOException {
		if (in == null || password == null || password.isEmpty() ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, false);
		JsonNode root = mapper.readTree(in);
		importDid(root, password, storepass);
	}

	/**
	 * Import DID information by input.
	 *
	 * @param in the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void importDid(Reader in, String password, String storepass)
			throws DIDStoreException, IOException {
		if (in == null || password == null || password.isEmpty() ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, false);
		JsonNode root = mapper.readTree(in);
		importDid(root, password, storepass);
	}

	/**
	 * Import DID information by input.
	 *
	 * @param file the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void importDid(File file, String password, String storepass)
			throws DIDStoreException, IOException {
		if (file == null || password == null || password.isEmpty() ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, false);
		JsonNode root = mapper.readTree(file);
		importDid(root, password, storepass);
	}

	/**
	 * Import DID information by input.
	 *
	 * @param file the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void importDid(String file, String password, String storepass)
			throws DIDStoreException, IOException {
		if (file == null || file.isEmpty() || password == null ||
				password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		importDid(new File(file), password, storepass);
	}

	private void exportPrivateIdentity(JsonGenerator generator, String password,
			String storepass) throws DIDStoreException, IOException {
		String encryptedKey = storage.loadPrivateIdentity();
		byte[] plain = decryptFromBase64(encryptedKey, storepass);
		encryptedKey = encryptToBase64(plain, password);
		Arrays.fill(plain, (byte)0);

		String encryptedMnemonic = null;
		if (storage.containsMnemonic()) {
			encryptedMnemonic = storage.loadMnemonic();
			plain = decryptFromBase64(encryptedMnemonic, storepass);
			encryptedMnemonic = encryptToBase64(plain, password);
			Arrays.fill(plain, (byte)0);
		}

		String pubKey = storage.containsPublicIdentity() ?
				storage.loadPublicIdentity() : null;

		int index = storage.loadPrivateIdentityIndex();

		SHA256Digest sha256 = new SHA256Digest();
		byte[] bytes = password.getBytes();
		sha256.update(bytes, 0, bytes.length);

		generator.writeStartObject();

		// Type
		generator.writeStringField("type", DID_EXPORT);
		bytes = DID_EXPORT.getBytes();
		sha256.update(bytes, 0, bytes.length);

		// Mnemonic
		if (encryptedMnemonic != null) {
			generator.writeStringField("mnemonic", encryptedMnemonic);
			bytes = encryptedMnemonic.getBytes();
			sha256.update(bytes, 0, bytes.length);
		}

		// Key
		generator.writeStringField("key", encryptedKey);
		bytes = encryptedKey.getBytes();
		sha256.update(bytes, 0, bytes.length);

		// Key.pub
		if (pubKey != null) {
			generator.writeStringField("key.pub", pubKey);
			bytes = pubKey.getBytes();
			sha256.update(bytes, 0, bytes.length);
		}

		// Index
		generator.writeNumberField("index", index);
		bytes = Integer.toString(index).getBytes();
		sha256.update(bytes, 0, bytes.length);

		// Fingerprint
		byte digest[] = new byte[32];
		sha256.doFinal(digest, 0);
		String fingerprint = Base64.encodeToString(digest,
				Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
		generator.writeStringField("fingerprint", fingerprint);

		generator.writeEndObject();
	}

	/**
     * Export private identity information into file with json format.
     * The json content include mnemonic(encrypted), extended private key(encrypted),
     * extended public key(if has it, dont't encrypted) and index.
	 *
	 * @param out the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void exportPrivateIdentity(OutputStream out, String password,
			String storepass) throws DIDStoreException, IOException {
		if (out == null || password == null || password.isEmpty() ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		JsonFactory factory = new JsonFactory();
		JsonGenerator generator = factory.createGenerator(out);
		generator.configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false);
		exportPrivateIdentity(generator, password, storepass);
		generator.close();
	}

	/**
     * Export private identity information into file with json format.
     * The json content include mnemonic(encrypted), extended private key(encrypted),
     * extended public key(if has it, dont't encrypted) and index.
	 *
	 * @param out the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void exportPrivateIdentity(Writer out, String password,
			String storepass) throws DIDStoreException, IOException {
		if (out == null || password == null || password.isEmpty()
				|| storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		JsonFactory factory = new JsonFactory();
		JsonGenerator generator = factory.createGenerator(out);
		generator.configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false);
		exportPrivateIdentity(generator, password, storepass);
		generator.close();
	}

	/**
     * Export private identity information into file with json format.
     * The json content include mnemonic(encrypted), extended private key(encrypted),
     * extended public key(if has it, dont't encrypted) and index.
	 *
	 * @param file the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void exportPrivateIdentity(File file, String password,
			String storepass) throws DIDStoreException, IOException {
		if (file == null || password == null || password.isEmpty()
				|| storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		exportPrivateIdentity(new FileWriter(file), password, storepass);
	}

	/**
     * Export private identity information into file with json format.
     * The json content include mnemonic(encrypted), extended private key(encrypted),
     * extended public key(if has it, dont't encrypted) and index.
	 *
	 * @param file the export output
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void exportPrivateIdentity(String file, String password,
			String storepass) throws DIDStoreException, IOException {
		if (file == null || file.isEmpty() || password == null ||
				password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		exportPrivateIdentity(new File(file), password, storepass);
	}

	private void importPrivateIdentity(JsonNode root, String password,
			String storepass) throws DIDStoreException, IOException {
		Class<DIDStoreException> exceptionClass = DIDStoreException.class;

		SHA256Digest sha256 = new SHA256Digest();
		byte[] bytes = password.getBytes();
		sha256.update(bytes, 0, bytes.length);

		// Type
		String type = JsonHelper.getString(root, "type", false, null,
				"export type", exceptionClass);
		if (!type.equals(DID_EXPORT))
			throw new DIDStoreException("Invalid export data, unknown type.");
		bytes = type.getBytes();
		sha256.update(bytes, 0, bytes.length);

		// Mnemonic
		String encryptedMnemonic = JsonHelper.getString(root, "mnemonic",
				true, null, "mnemonic", exceptionClass);
		if (encryptedMnemonic != null) {
			bytes = encryptedMnemonic.getBytes();
			sha256.update(bytes, 0, bytes.length);
		}

		byte[] plain = decryptFromBase64(encryptedMnemonic, password);
		encryptedMnemonic = encryptToBase64(plain, storepass);
		Arrays.fill(plain, (byte)0);

		// Key
		String encryptedKey = JsonHelper.getString(root, "key",
				false, null, "key", exceptionClass);
		bytes = encryptedKey.getBytes();
		sha256.update(bytes, 0, bytes.length);

		plain = decryptFromBase64(encryptedKey, password);
		encryptedKey = encryptToBase64(plain, storepass);
		Arrays.fill(plain, (byte)0);

		// Key.pub
		String pubKey = JsonHelper.getString(root, "key.pub",
				true, null, "publickey", exceptionClass);
		if (pubKey != null) {
			bytes = pubKey.getBytes();
			sha256.update(bytes, 0, bytes.length);
		}

		// Index
		JsonNode node = root.get("index");
		if (node == null || !node.isNumber())
			throw new DIDStoreException("Invalid export data, unknow index.");
		int index = node.asInt();
		bytes = Integer.toString(index).getBytes();
		sha256.update(bytes, 0, bytes.length);

		// Fingerprint
		node = root.get("fingerprint");
		if (node == null)
			throw new DIDStoreException("Missing fingerprint in the export data");
		String refFingerprint = node.asText();

		byte digest[] = new byte[32];
		sha256.doFinal(digest, 0);
		String fingerprint = Base64.encodeToString(digest,
				Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);

		if (!fingerprint.equals(refFingerprint))
			throw new DIDStoreException("Invalid export data, the fingerprint mismatch.");

		// Save
		if (encryptedMnemonic != null)
			storage.storeMnemonic(encryptedMnemonic);

		storage.storePrivateIdentity(encryptedKey);

		if (pubKey != null)
			storage.storePublicIdentity(pubKey);

		storage.storePrivateIdentityIndex(index);
	}


	/**
     * Import private identity by input.
	 *
	 * @param in the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password to DIDStore
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void importPrivateIdentity(InputStream in, String password,
			String storepass) throws DIDStoreException, IOException {
		if (in == null || password == null || password.isEmpty() ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, false);
		JsonNode root = mapper.readTree(in);
		importPrivateIdentity(root, password, storepass);
	}

	/**
     * Import private identity by input.
	 *
	 * @param in the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password to DIDStore
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void importPrivateIdentity(Reader in, String password,
			String storepass) throws DIDStoreException, IOException {
		if (in == null || password == null || password.isEmpty() ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, false);
		JsonNode root = mapper.readTree(in);
		importPrivateIdentity(root, password, storepass);
	}

	/**
     * Import private identity by input.
	 *
	 * @param in the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password to DIDStore
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void importPrivateIdentity(File file, String password,
			String storepass) throws DIDStoreException, IOException {
		if (file == null || password == null || password.isEmpty() ||
				storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, false);
		JsonNode root = mapper.readTree(file);
		importPrivateIdentity(root, password, storepass);
	}

	/**
     * Import private identity by input.
	 *
	 * @param in the import input
	 * @param password the password to decrypt private key in input
	 * @param storepass the password to DIDStore
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void importPrivateIdentity(String file, String password,
			String storepass) throws DIDStoreException, IOException {
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
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
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
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
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
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
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
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void importStore(ZipInputStream in, String password, String storepass)
			throws DIDStoreException, IOException {
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
	 * @param file the import zip file
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void importStore(File zipFile, String password, String storepass)
			throws DIDStoreException, IOException {
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
	 * @param file the import zip file
	 * @param password the password to encrypt the private key in output
	 * @param storepass the password for DIDStore
	 * @throws DIDStoreException DIDStore error.
	 * @throws IOException write json string failed.
	 */
	public void importStore(String zipFile, String password, String storepass)
			throws DIDStoreException, IOException {
		if (zipFile == null || zipFile.isEmpty() || password == null
				|| password.isEmpty() || storepass == null || storepass.isEmpty())
			throw new IllegalArgumentException();

		importStore(new File(zipFile), password, storepass);
	}
}
