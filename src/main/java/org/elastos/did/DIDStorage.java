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

import org.elastos.did.exception.DIDStorageException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.metadata.CredentialMetadataImpl;
import org.elastos.did.metadata.DIDMetadataImpl;

/**
 * The interface for DIDStorage to support different file system.
 */
public interface DIDStorage {
	/**
	 * The inferface to change password.
	 */
	public interface ReEncryptor {
		/**
		 * Reencrypt in the changing password.
		 *
		 * @param data the data need to reencrypted
		 * @return the reencrypted data
		 * @throws DIDStoreException DIDStore error.
		 */
		public String reEncrypt(String data) throws DIDStoreException;
	};

	/**
	 * Judge whether private identity exists in DIDStorage.
	 *
	 * @return the returned value is true if private identity exists;
	 *         the returned value if false if private identity does not exist.
	 * @throws DIDStorageException Unsupport the specified store type.
	 */
	public boolean containsPrivateIdentity() throws DIDStorageException;

	/**
	 * Store private identity.
	 *
	 * @param key the private identity
	 * @throws DIDStorageException store private identity failed.
	 */
	public void storePrivateIdentity(String key) throws DIDStorageException;

	/**
	 * Load private identity.
	 *
	 * @return the private identity from file
	 * @throws DIDStorageException load private identity failed.
	 */
	public String loadPrivateIdentity() throws DIDStorageException;

	/**
	 * Judge whether there is public identity in the DIDStore.
	 *
	 * @return the returned value is true if there is public identity in the DIDStorage;
	 *         the returned value is false if there is no public identity in the DIDStorage.
	 * @throws DIDStorageException DIDStorage error.
	 */
	public boolean containsPublicIdentity() throws DIDStorageException;

	/**
	 * Store public identity.
	 *
	 * @param key the extended public key
	 * @throws DIDStorageException DIDStorage error.
	 */
	public void storePublicIdentity(String key) throws DIDStorageException;

	/**
	 * Load public identity.
	 *
	 * @return the extended public key
	 * @throws DIDStorageException DIDStorage error.
	 */
	public String loadPublicIdentity() throws DIDStorageException;

	/**
	 * Store index.
	 *
	 * @param index the index
	 * @throws DIDStorageException DIDStorage error.
	 */
	public void storePrivateIdentityIndex(int index) throws DIDStorageException;

	/**
	 * Load index.
	 *
	 * @return the index
	 * @throws DIDStorageException DIDStorage error.
	 */
	public int loadPrivateIdentityIndex() throws DIDStorageException;

	/**
	 * Judge whether there is mnemonic in the DIDStorage.
	 *
	 * @return the retuened value is true if there is mnemonic in the DIDStorage;
	 *         the retuened value is false if there is no mnemonic in the DIDStorage
	 * @throws DIDStorageException DIDStorage error.
	 */
	public boolean containsMnemonic() throws DIDStorageException;

	/**
	 * Store mnemonic.
	 *
	 * @param mnemonic the mnemonic string
	 * @throws DIDStorageException DIDStorage error.
	 */
	public void storeMnemonic(String mnemonic) throws DIDStorageException;

	/**
	 * Load mnemonic.
	 *
	 * @return the mnemonic string
	 * @throws DIDStorageException DIDStorage error.
	 */
	public String loadMnemonic() throws DIDStorageException;

	/**
	 * Store DID Metadata.
	 *
	 * @param did the owner of Metadata
	 * @param metadata the meta data
	 * @throws DIDStorageException DIDStorage error.
	 */
	public void storeDidMetadata(DID did, DIDMetadataImpl metadata) throws DIDStorageException;

	/**
	 * Load DID Metadata.
	 *
	 * @param did the owner of Metadata.
	 * @return the meta data
	 * @throws DIDStorageException DIDStorage error.
	 */
	public DIDMetadataImpl loadDidMetadata(DID did) throws DIDStorageException;

	/**
	 * Store DID Document.
	 *
	 * @param doc the DIDDocument object.
	 * @throws DIDStorageException DIDStorage error.
	 */
	public void storeDid(DIDDocument doc) throws DIDStorageException;

	/**
	 * Load DID content(DIDDocument).
	 *
	 * @param did the specified DID
	 * @return the DID Document object
	 * @throws DIDStorageException DIDStorage error.
	 */
	public DIDDocument loadDid(DID did) throws DIDStorageException;

	/**
     * Judge whether containing the specified DID or not.
     *
     * @param did the specified DID
     * @return the returned value is true if the specified DID is in the DIDStorage;
     *         the returned value is false if the specified DID is not in the DIDStorage.
     * @throws DIDStorageException DIDStorage error.
	 */
	public boolean containsDid(DID did) throws DIDStorageException;

	/**
     * Delete the specified DID.
     *
     * @param did the specified DID
     * @return the returned value is true if deleting is successful;
     *         the returned value is false if deleting is failed.
     * @throws DIDStorageException DIDStorage error.
	 */
	public boolean deleteDid(DID did) throws DIDStorageException;

	/**
	 * List all DIDs according to the specified condition.
	 *
	 * @param filter the specified condition.
	 *               0: all did; 1: did has privatekeys;
     *               2: did has no privatekeys.
	 * @return the DID array.
	 * @throws DIDStorageException DIDStorage error.
	 */
	public List<DID> listDids(int filter) throws DIDStorageException;

	/**
     * Store meta data for the specified Credential.
     *
     * @param did the owner of the specified Credential
     * @param id the identifier of Credential
     * @param metadata the meta data for Credential
     * @throws DIDStorageException DIDStorage error.
	 */
	public void storeCredentialMetadata(DID did, DIDURL id, CredentialMetadataImpl metadata)
			throws DIDStorageException;

	/**
	 * Load the meta data about the specified Credential.
	 *
	 * @param did the owner of Credential
     * @param id the identifier of Credential
	 * @return the meta data for Credential
	 * @throws DIDStorageException DIDStorage error.
	 */
	public CredentialMetadataImpl loadCredentialMetadata(DID did, DIDURL id)
			throws DIDStorageException;

	/**
	 * Store the specified Credential.
	 *
	 * @param credential the Credential object
	 * @throws DIDStorageException DIDStorage error.
	 */
	public void storeCredential(VerifiableCredential credential)
			throws DIDStorageException;

	/**
	 * Load the specified Credential.
	 *
	 * @param did the owner of Credential
	 * @param id the identifier of Credential
	 * @return the Credential object
	 * @throws DIDStorageException DIDStorage error.
	 */
	public VerifiableCredential loadCredential(DID did, DIDURL id)
			throws DIDStorageException;

	/**
	 * Judge whether does DIDStore contain any credential owned the specific DID.
	 *
	 * @param did the owner of Credential
	 * @return the returned value is true if there is no credential owned the specific DID.
	 * @throws DIDStorageException DIDStorage error.
	 */
	public boolean containsCredentials(DID did) throws DIDStorageException;

	/**
	 * Judge whether does DIDStore contain the specified credential.
	 *
	 * @param did the owner of Credential
	 * @param id the identifier of Credential
	 * @return the returned value is true if there is no credential owned the specific DID;
	 *         the returned value is false if there is credentials owned the specific DID.
	 * @throws DIDStorageException DIDStorage error.
	 */
	public boolean containsCredential(DID did, DIDURL id)
			throws DIDStorageException;

	/**
	 * Delete the specified Credential
	 *
	 * @param did the owner of Credential
	 * @param id the identifier of Credential
	 * @return the returned value is true if there is no credential owned the specific DID;
	 *         the returned value is false if there is credentials owned the specific DID.
	 * @throws DIDStorageException DIDStorage error.
	 */
	public boolean deleteCredential(DID did, DIDURL id)
			throws DIDStorageException;

	/**
	 * List the Credentials owned the specified DID.
	 *
	 * @param did the owner of Credential
	 * @return the Credential array owned the specified DID.
	 * @throws DIDStorageException DIDStorage error.
	 */
	public List<DIDURL> listCredentials(DID did) throws DIDStorageException;

	/**
	 * Select the Credentials according to the specified condition.
	 *
	 * @param did the owner of Credential
	 * @param id the identifier of Credential
	 * @param type the Credential type
	 * @return the Credential array
	 * @throws DIDStorageException DIDStorage error.
	 */
	public List<DIDURL> selectCredentials(DID did, DIDURL id, String[] type)
			throws DIDStorageException;

	/**
	 * Store private key. Encrypt and encode private key with base64url method.
	 *
	 * @param did the owner of key
	 * @param id the identifier of key
	 * @param privateKey the original private key(32 bytes)
	 * @throws DIDStorageException DIDStorage error.
	 */
	public void storePrivateKey(DID did, DIDURL id, String privateKey)
			throws DIDStorageException;

	/**
	 * Load private key.
	 *
	 * @param did the owner of key
	 * @param id the identifier of key
	 * @return the encrypted private key
	 * @throws DIDStorageException DIDStorage error.
	 */
	public String loadPrivateKey(DID did, DIDURL id)
			throws DIDStorageException;

	/**
	 * Judge whether there is private key owned the specified DID in DIDStore.
	 *
	 * @param did the specified DID
	 * @return the returned value is true if there is private keys owned the specified DID;
	 *         the returned value is false if there is no private keys owned the specified DID.
	 * @throws DIDStorageException DIDStorage error.
	 */
	public boolean containsPrivateKeys(DID did) throws DIDStorageException;

	/**
	 * Judge that the specified key has private key in DIDStore.
	 *
	 * @param did the owner of key
	 * @param id the identifier of key
	 * @return the returned value is true if there is private keys owned the specified key;
	 *         the returned value is false if there is no private keys owned the specified key.
	 * @throws DIDStorageException DIDStorage error.
	 */
	public boolean containsPrivateKey(DID did, DIDURL id)
			throws DIDStorageException;

	/**
	 * Delete the private key owned to the specified key.
	 *
	 * @param did the owner of key
	 * @param id the identifier of key
	 * @return the returned value is true if deleting private keys successfully;
	 *         the returned value is false if deleting private keys failed.
	 * @throws DIDStorageException DIDStorage error.
	 */
	public boolean deletePrivateKey(DID did, DIDURL id)
			throws DIDStorageException;

    /**
     * Change password for DIDStore.
     *
     * @param reEncryptor the ReEncryptor handle
     * @throws DIDStorageException DIDStorage error.
     */
	public void changePassword(ReEncryptor reEncryptor)
			throws DIDStorageException;
}
