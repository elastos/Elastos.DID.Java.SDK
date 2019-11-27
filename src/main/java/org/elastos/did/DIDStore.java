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

import java.util.List;
import java.util.Map;

import org.elastos.credential.MalformedCredentialException;
import org.elastos.credential.VerifiableCredential;
import org.elastos.did.backend.DIDBackend;
import org.elastos.did.util.Aes256cbc;
import org.elastos.did.util.Base64;
import org.elastos.did.util.EcdsaSigner;
import org.elastos.did.util.HDKey;

public abstract class DIDStore {
	public static final int DID_HAS_PRIVATEKEY = 0;
	public static final int DID_NO_PRIVATEKEY = 1;
	public static final int DID_ALL	= 2;

	private static DIDStore instance;

	private DIDBackend backend;

	static public class Entry<K, V> implements java.io.Serializable {
		private static final long serialVersionUID = -4061538310957041415L;

		private final K key;
		private V value;

		public Entry(K key, V value) {
			this.key = key;
			this.value = value;
		}

		public Entry(Entry<? extends K, ? extends V> entry) {
			this.key = entry.getKey();
			this.value = entry.getValue();
		}

		public K getKey() {
			return key;
		}

		public V getValue() {
			return value;
		}

		public V setValue(V value) {
			V oldValue = this.value;
			this.value = value;
			return oldValue;
		}

		private static boolean eq(Object o1, Object o2) {
			return o1 == null ? o2 == null : o1.equals(o2);
		}

		@Override
		public boolean equals(Object o) {
			if (!(o instanceof Map.Entry))
				return false;
			Map.Entry<?, ?> e = (Map.Entry<?, ?>) o;
			return eq(key, e.getKey()) && eq(value, e.getValue());
		}

		@Override
		public int hashCode() {
			return (key == null   ? 0 : key.hashCode()  ) ^
				   (value == null ? 0 : value.hashCode());
		}

		@Override
		public String toString() {
			return key + "=" + value;
		}

	}

	public static void initialize(String type, String location,
			DIDAdapter adapter) throws DIDStoreException {
		if (type == null || location == null ||
				location.isEmpty() || adapter == null)
			throw new IllegalArgumentException();

		if (!type.equals("filesystem"))
			throw new DIDStoreException("Unsupported store type: " + type);

		instance = new FileSystemStore(location);
		instance.backend = new DIDBackend(adapter);
	}

	public static DIDStore getInstance() throws DIDStoreException {
		if (instance == null)
			throw new DIDStoreException("Store not initialized.");

		return instance;
	}

	protected DIDAdapter getAdapter() {
		return backend.getAdapter();
	}

	public abstract boolean hasPrivateIdentity() throws DIDStoreException;

	protected abstract void storePrivateIdentity(String key)
			throws DIDStoreException;

	protected abstract String loadPrivateIdentity() throws DIDStoreException;

	protected abstract void storePrivateIdentityIndex(int index)
			throws DIDStoreException;

	protected abstract int loadPrivateIdentityIndex() throws DIDStoreException;

	private static String encryptToBase64(String passwd, byte[] input)
			throws DIDStoreException {
		byte[] cipher;
		try {
			cipher = Aes256cbc.encrypt(passwd, input);
		} catch (Exception e) {
			throw new DIDStoreException("Encrypt key error.", e);
		}

		return Base64.encodeToString(cipher,
				Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
	}

	private static byte[] decryptFromBase64(String passwd, String input)
			throws DIDStoreException {
		byte[] cipher = Base64.decode(input,
				Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
		try {
			return Aes256cbc.decrypt(passwd, cipher);
		} catch (Exception e) {
			throw new DIDStoreException("Decrypt key error.", e);
		}
	}

	// Initialize & create new private identity and save it to DIDStore.
	public void initPrivateIdentity(int language, String mnemonic,
			String passphrase, String storepass, boolean force)
					throws DIDStoreException {
		if (!Mnemonic.isValid(language, mnemonic))
			throw new IllegalArgumentException("Invalid mnemonic.");

		if (storepass == null)
			throw new IllegalArgumentException("Invalid password.");

		if (hasPrivateIdentity() && !force)
			throw new DIDStoreException("Already has private indentity.");

		if (passphrase == null)
			passphrase = "";

		HDKey privateIdentity = HDKey.fromMnemonic(mnemonic, passphrase);

		// Save seed instead of root private key,
		// keep compatible with Native SDK
		String encryptedIdentity = encryptToBase64(storepass,
				privateIdentity.getSeed());
		storePrivateIdentity(encryptedIdentity);
		storePrivateIdentityIndex(0);

		privateIdentity.wipe();
	}

	public void initPrivateIdentity(int language, String mnemonic,
			String passphrase, String storepass) throws DIDStoreException {
		initPrivateIdentity(language, mnemonic, passphrase, storepass, false);
	}

	// initialized from saved private identity from DIDStore.
	protected HDKey loadPrivateIdentity(String storepass)
			throws DIDStoreException {
		if (!hasPrivateIdentity())
			return null;

		byte[] seed = decryptFromBase64(storepass, loadPrivateIdentity());
		return HDKey.fromSeed(seed);
	}

	public void synchronize(String storepass) throws DIDStoreException  {
		if (storepass == null)
			throw new IllegalArgumentException("Invalid password.");

		HDKey privateIdentity = loadPrivateIdentity(storepass);
		if (privateIdentity == null)
			throw new DIDStoreException("DID Store not contains private identity.");

		int nextIndex = loadPrivateIdentityIndex();
		int blanks = 0;
		int i = 0;

		while (i < nextIndex || blanks < 10) {
			HDKey.DerivedKey key = privateIdentity.derive(i++);
			DID did = new DID(DID.METHOD, key.getAddress());

			DIDDocument doc = backend.resolve(did);
			if (doc != null) {
				// TODO: check local conflict
				storeDid(doc);

				// Save private key
				String encryptedKey = encryptToBase64(storepass, key.serialize());
				storePrivateKey(did, doc.getDefaultPublicKey(), encryptedKey);

				if (i >= nextIndex)
					storePrivateIdentityIndex(i);

				blanks = 0;
			} else {
				blanks++;
			}
		}
	}

	public DIDDocument newDid(String storepass, String hint)
			throws DIDStoreException {
		if (storepass == null)
			throw new IllegalArgumentException("Invalid password.");

		HDKey privateIdentity = loadPrivateIdentity(storepass);
		if (privateIdentity == null)
			throw new DIDStoreException("DID Store not contains private identity.");

		int nextIndex = loadPrivateIdentityIndex();

		HDKey.DerivedKey key = privateIdentity.derive(nextIndex++);
		DID did = new DID(DID.METHOD, key.getAddress());
		PublicKey pk = new PublicKey(new DIDURL(did, "primary"),
				Constants.defaultPublicKeyType, did, key.getPublicKeyBase58());

		DIDDocument doc = new DIDDocument();
		doc.setSubject(did);
		doc.addPublicKey(pk);
		doc.addAuthenticationKey(pk);
		doc.setReadonly(true);

		storeDid(doc, hint);

		String encryptedKey = encryptToBase64(storepass, key.serialize());
		storePrivateKey(did, pk.getId(), encryptedKey);
		storePrivateIdentityIndex(nextIndex);

		privateIdentity.wipe();
		key.wipe();

		return doc;
	}

	public DIDDocument newDid(String storepass) throws DIDStoreException {
		return newDid(storepass, null);
	}

	public boolean publishDid(DIDDocument doc, DIDURL signKey, String storepass)
			throws DIDStoreException {
		if (doc == null || storepass == null)
			throw new IllegalArgumentException();

		if (signKey == null)
			signKey = doc.getDefaultPublicKey();

		storeDid(doc);
		return backend.create(doc, signKey, storepass);
	}

	public boolean publishDid(DIDDocument doc, String signKey, String storepass)
			throws MalformedDIDURLException, DIDStoreException {
		DIDURL id = signKey == null ? null : new DIDURL(doc.getSubject(), signKey);
		return publishDid(doc, id, storepass);
	}

	public boolean publishDid(DIDDocument doc, String storepass)
			throws DIDStoreException {
		return publishDid(doc, (DIDURL)null, storepass);
	}

	public boolean updateDid(DIDDocument doc, DIDURL signKey, String storepass)
			throws DIDStoreException {
		if (doc == null || storepass == null)
			throw new IllegalArgumentException();

		if (signKey == null)
			signKey = doc.getDefaultPublicKey();

		storeDid(doc);
		return backend.update(doc, signKey, storepass);
	}

	public boolean updateDid(DIDDocument doc, String signKey, String storepass)
			throws MalformedDIDURLException, DIDStoreException {
		DIDURL id = signKey == null ? null : new DIDURL(doc.getSubject(), signKey);
		return updateDid(doc, id, storepass);
	}

	public boolean updateDid(DIDDocument doc, String storepass)
			throws DIDStoreException {
		return updateDid(doc, (DIDURL)null, storepass);
	}

	public boolean deactivateDid(DID did, DIDURL signKey, String storepass)
			throws DIDStoreException {
		if (did == null || storepass == null)
			throw new IllegalArgumentException();

		if (signKey == null) {
			try {
				DIDDocument doc = resolveDid(did);
				if (doc == null)
					throw new DIDStoreException("Can not resolve DID document.");

				signKey = doc.getDefaultPublicKey();
			} catch (MalformedDocumentException e) {
				throw new DIDStoreException(e);
			}
		}

		return backend.deactivate(did, signKey, storepass);

		// TODO: how to handle locally?
	}

	public boolean deactivateDid(DID did, String signKey, String storepass)
			throws MalformedDIDURLException, DIDStoreException {
		DIDURL id = signKey == null ? null : new DIDURL(did, signKey);
		return deactivateDid(did, id, storepass);
	}

	public boolean deactivateDid(DID did, String storepass)
			throws DIDStoreException {
		return deactivateDid(did, (DIDURL)null, storepass);
	}

	public DIDDocument resolveDid(DID did, boolean force)
			throws DIDStoreException, MalformedDocumentException {
		if (did == null)
			throw new IllegalArgumentException();

		DIDDocument doc = backend.resolve(did);
		if (doc != null)
			storeDid(doc);

		if (doc == null && !force)
			doc = loadDid(did);

		return doc;
	}

	public DIDDocument resolveDid(String did, boolean force)
			throws MalformedDIDException, MalformedDocumentException,
			DIDStoreException  {
		return resolveDid(new DID(did), force);
	}

	public DIDDocument resolveDid(DID did)
			throws DIDStoreException, MalformedDocumentException {
		return resolveDid(did, false);
	}

	public DIDDocument resolveDid(String did)
			throws MalformedDIDException, MalformedDocumentException,
			DIDStoreException  {
		return resolveDid(did, false);
	}

	public abstract void storeDid(DIDDocument doc, String hint)
			throws DIDStoreException;

	public void storeDid(DIDDocument doc) throws DIDStoreException {
		storeDid(doc, null);
	}

	public abstract void setDidHint(DID did, String hint)
			throws DIDStoreException;

	public void setDidHint(String did, String hint)
			throws MalformedDIDException, DIDStoreException {
		setDidHint(new DID(did), hint);
	}

	public abstract String getDidHint(DID did) throws DIDStoreException;

	public String getDidHint(String did)
			throws MalformedDIDException, DIDStoreException {
		return getDidHint(new DID(did));
	}

	public abstract DIDDocument loadDid(DID did)
			throws MalformedDocumentException, DIDStoreException;

	public DIDDocument loadDid(String did)
			throws MalformedDIDException, MalformedDocumentException,
			DIDStoreException {
		return loadDid(new DID(did));
	}

	public abstract boolean containsDid(DID did) throws DIDStoreException;

	public boolean containsDid(String did)
			throws MalformedDIDException, DIDStoreException {
		return containsDid(new DID(did));
	}

	public abstract boolean deleteDid(DID did) throws DIDStoreException;

	public boolean deleteDid(String did)
			throws MalformedDIDException, DIDStoreException {
		return deleteDid(new DID(did));
	}

	// Return a <DID, hint> tuples enumeration object
	public abstract List<Entry<DID, String>> listDids(int filter)
			throws DIDStoreException;

	public abstract void storeCredential(VerifiableCredential credential,
			String hint) throws DIDStoreException;

	public void storeCredential(VerifiableCredential credential)
			throws DIDStoreException {
		storeCredential(credential, null);
	}

	public abstract void setCredentialHint(DID did, DIDURL id, String hint)
			throws DIDStoreException;

	public void setCredentialHint(String did, String id, String hint)
			throws  MalformedDIDException, MalformedDIDURLException,
			DIDStoreException {
		DID _did = new DID(did);
		setCredentialHint(_did, new DIDURL(_did, id), hint);
	}

	public abstract String getCredentialHint(DID did, DIDURL id)
			throws DIDStoreException;

	public String getCredentialHint(String did, String id)
			throws  MalformedDIDException, MalformedDIDURLException,
			DIDStoreException {
		DID _did = new DID(did);
		return getCredentialHint(_did, new DIDURL(_did, id));
	}

	public abstract VerifiableCredential loadCredential(DID did, DIDURL id)
			throws MalformedCredentialException, DIDStoreException;

	public VerifiableCredential loadCredential(String did, String id)
			throws MalformedDIDException, MalformedDIDURLException,
			MalformedCredentialException, DIDStoreException {
		DID _did = new DID(did);
		return loadCredential(_did, new DIDURL(_did, id));
	}

	public abstract boolean containsCredentials(DID did) throws DIDStoreException;

	public boolean containsCredentials(String did)
			throws MalformedDIDException, DIDStoreException {
		return containsCredentials(new DID(did));
	}

	public abstract boolean containsCredential(DID did, DIDURL id)
			throws DIDStoreException;

	public boolean containsCredential(String did, String id)
			throws MalformedDIDException, MalformedDIDURLException,
			DIDStoreException {
		DID _did = new DID(did);
		return containsCredential(_did, new DIDURL(_did, id));
	}

	public abstract boolean deleteCredential(DID did, DIDURL id)
			throws DIDStoreException;

	public boolean deleteCredential(String did, String id)
			throws MalformedDIDException, MalformedDIDURLException,
			DIDStoreException {
		DID _did = new DID(did);
		return deleteCredential(_did, new DIDURL(_did, id));
	}

	// Return a <DIDURL, hint> tuples enumeration object
	public abstract List<Entry<DIDURL, String>> listCredentials(DID did)
			throws DIDStoreException;

	public List<Entry<DIDURL, String>> listCredentials(String did)
			throws MalformedDIDException, DIDStoreException {
		return listCredentials(new DID(did));
	}

	public abstract List<Entry<DIDURL, String>> selectCredentials(DID did,
			DIDURL id, String[] type) throws DIDStoreException;

	public List<Entry<DIDURL, String>> selectCredentials(String did, String id,
			String[] type) throws MalformedDIDException,
			MalformedDIDURLException, DIDStoreException {
		DID _did = new DID(did);
		return selectCredentials(_did, new DIDURL(_did, id), type);
	}

	public abstract boolean containsPrivateKeys(DID did)
			throws DIDStoreException;

	public boolean containsPrivateKeys(String did)
			throws MalformedDIDException, DIDStoreException {
		return containsPrivateKeys(new DID(did));
	}

	public abstract boolean containsPrivateKey(DID did, DIDURL id)
			throws DIDStoreException;

	public boolean containsPrivateKey(String did, String id)
			throws MalformedDIDException, MalformedDIDURLException,
			DIDStoreException {
		DID _did = new DID(did);
		return containsPrivateKey(_did, new DIDURL(_did, id));
	}

	public abstract void storePrivateKey(DID did, DIDURL id, String privateKey)
			throws DIDStoreException;

	public void storePrivateKey(String did, String id, String privateKey)
			throws MalformedDIDException, MalformedDIDURLException,
			DIDStoreException {
		DID _did = new DID(did);
		storePrivateKey(_did, new DIDURL(_did, id), privateKey);
	}

	protected abstract String loadPrivateKey(DID did, DIDURL id)
			throws DIDStoreException;

	public abstract boolean deletePrivateKey(DID did, DIDURL id)
			throws DIDStoreException;

	public boolean deletePrivateKey(String did, String id)
			throws MalformedDIDException, MalformedDIDURLException,
			DIDStoreException {
		DID _did = new DID(did);
		return deletePrivateKey(_did, new DIDURL(_did, id));
	}

	public String sign(DID did, DIDURL id, String storepass, byte[] ... data)
			throws DIDStoreException {
		if (did == null || storepass == null || data == null)
			throw new IllegalArgumentException();

		if (id == null) {
			try {
				DIDDocument doc = resolveDid(did);
				if (doc == null)
					throw new DIDStoreException("Can not resolve DID document.");

				id = doc.getDefaultPublicKey();
			} catch (MalformedDocumentException e) {
				throw new DIDStoreException(e);
			}
		}

		byte[] binKey = decryptFromBase64(storepass, loadPrivateKey(did, id));
		HDKey.DerivedKey key = HDKey.DerivedKey.deserialize(binKey);

		byte[] sig = EcdsaSigner.sign(key.getPrivateKeyBytes(), data);

		key.wipe();

		return Base64.encodeToString(sig,
				Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
	}

	public String sign(DID did, String storepass, byte[] ... data)
			throws DIDStoreException {
		return sign(did, null, storepass, data);
	}
}
