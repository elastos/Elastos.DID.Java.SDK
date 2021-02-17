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

	public String getLocation();

	public void storeMetadata(DIDStore.Metadata metadata) throws DIDStorageException;

	public DIDStore.Metadata loadMetadata() throws DIDStorageException;

	public void storeRootIdentityMetadata(String id, RootIdentity.Metadata metadata)
			throws DIDStorageException;

	/**
	 * Load DID Metadata.
	 *
	 * @param did the owner of Metadata.
	 * @return the meta data
	 * @throws DIDStorageException DIDStorage error.
	 */
	public RootIdentity.Metadata loadRootIdentityMetadata(String id)
			throws DIDStorageException;

	/**
	 * Store private identity.
	 *
	 * @param key the private identity
	 * @throws DIDStorageException store private identity failed.
	 */
	public void storeRootIdentity(String id, String mnemonic, String privateKey,
			String publicKey, int index) throws DIDStorageException;

	/**
	 * Load private identity.
	 *
	 * @return the private identity from file
	 * @throws DIDStorageException load private identity failed.
	 */
	public RootIdentity loadRootIdentity(String id) throws DIDStorageException;

	public void updateRootIdentityIndex(String id, int index)
			throws DIDStorageException;

	public String loadRootIdentityPrivateKey(String id) throws DIDStorageException;

	/**
	 * Load mnemonic.
	 *
	 * @return the mnemonic string
	 * @throws DIDStorageException DIDStorage error.
	 */
	public String loadRootIdentityMnemonic(String id) throws DIDStorageException;

	public boolean deleteRootIdentity(String id) throws DIDStorageException;

	public List<RootIdentity> listRootIdentities() throws DIDStorageException;

	public boolean containsRootIdenities() throws DIDStorageException;

	/**
	 * Store DID Metadata.
	 *
	 * @param did the owner of Metadata
	 * @param metadata the meta data
	 * @throws DIDStorageException DIDStorage error.
	 */
	public void storeDidMetadata(DID did, DIDMetadata metadata) throws DIDStorageException;

	/**
	 * Load DID Metadata.
	 *
	 * @param did the owner of Metadata.
	 * @return the meta data
	 * @throws DIDStorageException DIDStorage error.
	 */
	public DIDMetadata loadDidMetadata(DID did) throws DIDStorageException;

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
	 * @return the DID array.
	 * @throws DIDStorageException DIDStorage error.
	 */
	public List<DID> listDids() throws DIDStorageException;

	/**
     * Store meta data for the specified Credential.
     *
     * @param did the owner of the specified Credential
     * @param id the identifier of Credential
     * @param metadata the meta data for Credential
     * @throws DIDStorageException DIDStorage error.
	 */
	public void storeCredentialMetadata(DIDURL id, CredentialMetadata metadata)
			throws DIDStorageException;

	/**
	 * Load the meta data about the specified Credential.
	 *
	 * @param did the owner of Credential
     * @param id the identifier of Credential
	 * @return the meta data for Credential
	 * @throws DIDStorageException DIDStorage error.
	 */
	public CredentialMetadata loadCredentialMetadata(DIDURL id)
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
	public VerifiableCredential loadCredential(DIDURL id)
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
	 * Delete the specified Credential
	 *
	 * @param did the owner of Credential
	 * @param id the identifier of Credential
	 * @return the returned value is true if there is no credential owned the specific DID;
	 *         the returned value is false if there is credentials owned the specific DID.
	 * @throws DIDStorageException DIDStorage error.
	 */
	public boolean deleteCredential(DIDURL id)
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
	 * Store private key. Encrypt and encode private key with base64url method.
	 *
	 * @param did the owner of key
	 * @param id the identifier of key
	 * @param privateKey the original private key(32 bytes)
	 * @throws DIDStorageException DIDStorage error.
	 */
	public void storePrivateKey(DIDURL id, String privateKey)
			throws DIDStorageException;

	/**
	 * Load private key.
	 *
	 * @param did the owner of key
	 * @param id the identifier of key
	 * @return the encrypted private key
	 * @throws DIDStorageException DIDStorage error.
	 */
	public String loadPrivateKey(DIDURL id) throws DIDStorageException;

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
	 * Delete the private key owned to the specified key.
	 *
	 * @param did the owner of key
	 * @param id the identifier of key
	 * @return the returned value is true if deleting private keys successfully;
	 *         the returned value is false if deleting private keys failed.
	 * @throws DIDStorageException DIDStorage error.
	 */
	public boolean deletePrivateKey(DIDURL id) throws DIDStorageException;

	/**
	 * List the private keys owned the specified DID.
	 *
	 * @param did the owner of private key
	 * @return the private key array owned the specified DID.
	 * @throws DIDStorageException DIDStorage error.
	 */
	public List<DIDURL> listPrivateKeys(DID did) throws DIDStorageException;

    /**
     * Change password for DIDStore.
     *
     * @param reEncryptor the ReEncryptor handle
     * @throws DIDStorageException DIDStorage error.
     */
	public void changePassword(ReEncryptor reEncryptor)
			throws DIDStorageException;
}
