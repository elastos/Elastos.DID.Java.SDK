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

import java.text.ParseException;
import java.util.Date;

import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.UnknownInternalException;

/**
 * The object contains the information about the VerifiableCredential object.
 * the information may include the credential transaction information and user
 * defined information.
 */
public class CredentialMetadata extends AbstractMetadata implements Cloneable {
	private final static String TXID = "txid";
	private final static String PUBLISHED = "published";
	private final static String REVOKED = "revoked";

	private DIDURL id;

	/**
	 *  Default constructor.
	 */
	protected CredentialMetadata() {
		this(null);
	}

	/**
	 * Constructs a CredentialMetadata with given id.
	 *
	 * @param id a credential id
	 */
	protected CredentialMetadata(DIDURL id) {
		this(id, null);
	}

	/**
	 * Constructs a CredentialMetadata with given id and attach with
	 * a DID store.
	 *
	 * @param id a credential id
	 * @param store a DIDStore object
	 */
	protected CredentialMetadata(DIDURL id, DIDStore store) {
		super(store);
		this.id = id;
	}

	/**
	 * Set the credential id of this metadata object.
	 *
	 * @param id a credential id
	 */
	protected void setId(DIDURL id) {
		this.id = id;
	}

	/**
	 * Set the last transaction id of the credential that associated with
	 * this metadata object.
	 *
	 * @param txid a transaction id
	 */
	protected void setTransactionId(String txid) {
		put(TXID, txid);
	}

	/**
	 * Get the last transaction id of the credential that kept in this metadata
	 * object.
	 *
	 * @return the transaction id
	 */
	public String getTransactionId() {
		return get(TXID);
	}

	/**
	 * Set the publish time of the credential that associated with this
	 * metadata object.
	 *
	 * @param timestamp the publish time
	 */
	protected void setPublishTime(Date timestamp) {
		checkArgument(timestamp != null, "Invalid timestamp");

		put(PUBLISHED, timestamp);
	}

	/**
	 * Get the publish time of the credential that kept in this metadata
	 * object.
	 *
	 * @return the published time
	 */
	public Date getPublishTime() {
		try {
			return getDate(PUBLISHED);
		} catch (ParseException e) {
			return null;
		}
	}

	/**
	 * Set the revocation status of the credential that associated with this
	 * metadata object.
	 *
	 * @param revoked the revocation status
	 */
	protected void setRevoked(boolean revoked) {
		put(REVOKED, revoked);
	}

	/**
	 * Get the revocation status of the credential that kept in this metadata
	 * object.
	 *
	 * @return true if credential is revoked, otherwise false
	 */
	public boolean isRevoked( ) {
		return getBoolean(REVOKED);
	}

	/**
	 * Returns a shallow copy of this instance: the property names and values
	 * themselves are not cloned.
	 *
	 * @return a shallow copy of this object
	 */
	@Override
	public CredentialMetadata clone() {
		try {
			return (CredentialMetadata)super.clone();
		} catch (CloneNotSupportedException e) {
			throw new UnknownInternalException(e);
		}
	}

	/**
	 * Save this metadata object to the attached store if this metadata
	 * attached with a store.
	 */
	@Override
	protected void save() {
		if (attachedStore()) {
			try {
				getStore().storeCredentialMetadata(id, this);
			} catch (DIDStoreException e) {
				throw new UnknownInternalException(e);
			}
		}
	}
}
