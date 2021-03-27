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
 * The abstract storage interface for the DID store.
 */
public interface DIDStorage {
	/**
	 * Data re-encrypt interface used to change the password of the DIDStore.
	 *
	 * <p>
	 * The password of DIDStore is managed by the DIDStore, all stored data
	 * is transparent to the DIDStorage. Normally this interface is implemented
	 * by the DIDStore and provide to the DIDStore when change the password.
	 * All encrypted data will re-encrypt transparently through this interface.
	 * </p>
	 */
	public interface ReEncryptor {
		/**
		 * Re-encrypt the encrypted data.
		 *
		 * @param data the data need to be re-encrypt
		 * @return the re-encrypted data
		 * @throws DIDStoreException if an error occurred when re-encrypting data
		 */
		public String reEncrypt(String data) throws DIDStoreException;
	};

	/**
	 * Get the implement related storage location.
	 *
	 * @return a string representation of the location
	 */
	public String getLocation();

	/**
	 * Save the DIDStore's metadata object to the storage.
	 *
	 * @param metadata the metadata of DIDStore object
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public void storeMetadata(DIDStore.Metadata metadata) throws DIDStorageException;

	/**
	 * Read the DIDStore's metadata object from the storage.
	 *
	 * @return the metadata of DIDStore object
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public DIDStore.Metadata loadMetadata() throws DIDStorageException;

	/**
	 * Save the RootIdentity's metadata object to the storage.
	 *
	 * @param id the id of the RootIdentity
	 * @param metadata the metadata of RootIdentity object
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public void storeRootIdentityMetadata(String id, RootIdentity.Metadata metadata)
			throws DIDStorageException;

	/**
	 * Read the RootIdentity's metadata object from the storage.
	 *
	 * @param id the id of the RootIdentity
	 * @return the metadata of RootIdentity object
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public RootIdentity.Metadata loadRootIdentityMetadata(String id)
			throws DIDStorageException;

	/**
	 * Save the raw root identity to the storage.
	 *
	 * @param id the id of the RootIdentity
	 * @param mnemonic mnemonic words that the identity was generate from or null
	 * @param privateKey the encrypted private key of the RootIdentity
	 * @param publicKey the pre-derived public key of the RootIdentity
	 * @param index the index hint for DID deriving
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public void storeRootIdentity(String id, String mnemonic, String privateKey,
			String publicKey, int index) throws DIDStorageException;

	/**
	 * Read the RootIdentity object from the storage.
	 *
	 * @param id the id of the RootIdentity
	 * @return the RootIdentity object
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public RootIdentity loadRootIdentity(String id) throws DIDStorageException;

	/**
	 * Update the derive index of the RootIdentity.
	 *
	 * @param id the id of the RootIdentity
	 * @param index the new index hint
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public void updateRootIdentityIndex(String id, int index)
			throws DIDStorageException;

	/**
	 * Read the encrypted private key of the RootIdentity.
	 *
	 * @param id the id of the RootIdentity
	 * @return the encrypted private key
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public String loadRootIdentityPrivateKey(String id) throws DIDStorageException;

	/**
	 * Read the mnemonic that generate the RootIdentity.
	 *
	 * @param id the id of the RootIdentity
	 * @return the mnemonic string or null if not exists
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public String loadRootIdentityMnemonic(String id) throws DIDStorageException;

	/**
	 * Delete the specific RootIdentity object from the storage.
	 *
	 * @param id the id of the RootIdentity to be delete
	 * @return true if the RootIdentity exists and deleted successful, false otherwise
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public boolean deleteRootIdentity(String id) throws DIDStorageException;

	/**
	 * List the all RootIdentities that stored in this storage.
	 *
	 * @return an array of RootIdentity objects
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public List<RootIdentity> listRootIdentities() throws DIDStorageException;

	/**
	 * Check whether this storage contains RootIdentity objects.
	 *
	 * @return true if contains RootIdentity object, false otherwise
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public boolean containsRootIdenities() throws DIDStorageException;

	/**
	 * Save the DID metadata object to this storage.
	 *
	 * @param did the owner of the metadata object
	 * @param metadata a DIDMetadata object
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public void storeDidMetadata(DID did, DIDMetadata metadata) throws DIDStorageException;

	/**
	 * Read the DID metadata object from this storage.
	 *
	 * @param did the target DID object
	 * @return the DIDMetadata object
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public DIDMetadata loadDidMetadata(DID did) throws DIDStorageException;

	/**
	 * Save the DID document to this storage.
	 *
	 * @param doc a DIDDocument object
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public void storeDid(DIDDocument doc) throws DIDStorageException;

	/**
	 * Read the DID document from this storage.
	 *
	 * @param did the target DID object
	 * @return the DIDDocument object
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public DIDDocument loadDid(DID did) throws DIDStorageException;

	/**
	 * Delete the specified DID document object from this storage.
	 *
	 * @param did the target DID to be delete
	 * @return true if the DID exists and deleted successful, false otherwise
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public boolean deleteDid(DID did) throws DIDStorageException;

	/**
	 * List all DIDs that stored in this storage.
	 *
	 * @return an array of DID objects
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public List<DID> listDids() throws DIDStorageException;

	/**
	 * Save the credential's metadata to this storage.
	 *
	 * @param id the id of the credential
	 * @param metadata the credential's metadata object
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public void storeCredentialMetadata(DIDURL id, CredentialMetadata metadata)
			throws DIDStorageException;

	/**
	 * Read the credential's metadata object from this storage.
	 *
	 * @param id the id of the target credential
	 * @return the credential's metadata object
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public CredentialMetadata loadCredentialMetadata(DIDURL id)
			throws DIDStorageException;

	/**
	 * Save the credential object to this storage.
	 *
	 * @param credential a VerifiableCredential object
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public void storeCredential(VerifiableCredential credential)
			throws DIDStorageException;

	/**
	 * Read the specified credential object from this storage.
	 *
	 * @param id the id of the target credential
	 * @return the VerifiableCredential object
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public VerifiableCredential loadCredential(DIDURL id)
			throws DIDStorageException;

	/**
	 * Check whether this storage contains the credentials that owned by the
	 * given DID.
	 *
	 * @param did the target DID object
	 * @return true if contains credential object owned by the given DID,
	 * 		   false otherwise
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public boolean containsCredentials(DID did) throws DIDStorageException;

	/**
	 * Delete the specified credential from this storage.
	 *
	 * @param id the id of the target credential to be delete
	 * @return true if the credential exists and deleted successful, false otherwise
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public boolean deleteCredential(DIDURL id)
			throws DIDStorageException;

	/**
	 * List all credentials that owned the given DID.
	 *
	 * @param did a DID object
	 * @return an array of DIDURL denoting the credentials
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public List<DIDURL> listCredentials(DID did) throws DIDStorageException;

	/**
	 * Save the encrypted private key to this storage.
	 *
	 * @param id the key id
	 * @param privateKey the encrypted private key
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public void storePrivateKey(DIDURL id, String privateKey)
			throws DIDStorageException;

	/**
	 * Read the encrypted private key from this storage
	 *
	 * @param id the key id
	 * @return the encrypted private key
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public String loadPrivateKey(DIDURL id) throws DIDStorageException;

	/**
	 * Check whether this storage contains the private key that owned by the
	 * given DID.
	 *
	 * @param did the target DID object
	 * @return true if contains private key that owned by the given DID,
	 * 		   false otherwise
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public boolean containsPrivateKeys(DID did) throws DIDStorageException;

	/**
	 * Delete the specific private key from this storage.
	 *
	 * @param id the id of the key to be delete
	 * @return true if the key exists and deleted successful, false otherwise
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public boolean deletePrivateKey(DIDURL id) throws DIDStorageException;

	/**
	 * List the all private keys that owned by the given DID.
	 *
	 * @param did a DID object
	 * @return an array of DIDURL denoting the private keys
	 * @throws DIDStorageException if an error occurred when accessing the DID storage
	 */
	public List<DIDURL> listPrivateKeys(DID did) throws DIDStorageException;

	/**
	 * Change the password of the DIDStore.
	 *
	 * @param reEncryptor the data re-encrypt handler
	 * @throws DIDStorageException if an error occurred when re-encrypting data
	 */
	public void changePassword(ReEncryptor reEncryptor)
			throws DIDStorageException;
}
