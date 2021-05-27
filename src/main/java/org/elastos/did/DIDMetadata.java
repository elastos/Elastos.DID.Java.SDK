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

import java.text.ParseException;
import java.util.Date;

import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.UnknownInternalException;

/**
 * The object contains the information about the DID object.
 * the information may include the DID transaction information and user
 * defined information.
 */
public class DIDMetadata extends AbstractMetadata implements Cloneable {
	private final static String ROOT_IDENTITY = "rootIdentity";
	private final static String INDEX = "index";
	private final static String TXID = "txid";
	private final static String PREV_SIGNATURE = "prevSignature";
	private final static String SIGNATURE = "signature";
	private final static String PUBLISHED = "published";
	private final static String DEACTIVATED = "deactivated";

	private DID did;

	/**
	 *  Default constructor.
	 */
	protected DIDMetadata() {
		this(null);
	}

	/**
	 * Constructs a CredentialMetadata with given did.
	 *
	 * @param did a DID object
	 */
	protected DIDMetadata(DID did) {
		this(did, null);
	}

	/**
	 * Constructs a DIDMetadata with given did and attach with a DID store.
	 *
	 * @param did a DID object
	 * @param store a DIDStore object
	 */
	protected DIDMetadata(DID did, DIDStore store) {
		super(store);
		this.did = did;
	}

	/**
	 * Set the DID of this metadata object.
	 *
	 * @param id a credential id
	 */
	protected void setDid(DID did) {
		this.did = did;
	}

	/**
	 * Set the root identity id that the DID derived from, if the DID
	 * is derived from a root identity.
	 *
	 * @param id a root identity id
	 */
	protected void setRootIdentityId(String id) {
		put(ROOT_IDENTITY, id);
	}

	/**
	 * Get the root identity id that the DID derived from.
	 * Null if the DID is not derived from a root identity.
	 *
	 * @return the root identity id
	 */
	protected String getRootIdentityId() {
		return get(ROOT_IDENTITY);
	}

	/**
	 * Set the derived index if the DID is derived from a root identity.
	 *
	 * @param id a derive index
	 */
	protected void setIndex(int index) {
		put(INDEX, index);
	}

	/**
	 * Get the derived index only if the DID is derived from a root identity.
	 *
	 * @param id a derive index
	 */
	protected int getIndex() {
		try {
			return getInteger(INDEX);
		} catch (NumberFormatException e) {
			return -1;
		}
	}

	/**
	 * Set the last transaction id of the DID that associated with
	 * this metadata object.
	 *
	 * @param txid a transaction id
	 */
	protected void setTransactionId(String txid) {
		put(TXID, txid);
	}

	/**
	 * Get the last transaction id of the DID that kept in this metadata
	 * object.
	 *
	 * @return the transaction id
	 */
	public String getTransactionId() {
		return get(TXID);
	}

	/**
	 * Set the previous signature of the DID document that associated with this
	 * metadata object.
	 *
	 * @param signature the signature string
	 */
	protected void setPreviousSignature(String signature) {
		put(PREV_SIGNATURE, signature);
	}

	/**
	 * Get the previous document signature from the previous transaction.
	 *
	 * @return the signature string
	 */
	public String getPreviousSignature() {
		return get(PREV_SIGNATURE);
	}

	/**
	 * Set the latest signature of the DID document that associated with this
	 * metadata object.
	 *
	 * @param signature the signature string
	 */
	protected void setSignature(String signature) {
		put(SIGNATURE, signature);
	}

	/**
	 * Get the signature of the DID document that kept in this metadata object.
	 *
	 * @return the signature string
	 */
	public String getSignature() {
		return get(SIGNATURE);
	}

	/**
	 * Set the publish time of the DID that associated with this
	 * metadata object.
	 *
	 * @param timestamp the publish time
	 */
	protected void setPublishTime(Date timestamp) {
		put(PUBLISHED, timestamp);
	}

	/**
	 * Get the publish time of the DID that kept in this metadata
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
	 * Set the deactivated status of the DID that associated with this
	 * metadata object.
	 *
	 * @param deactivated the deactivated status
	 */
	protected void setDeactivated(boolean deactivated) {
		put(DEACTIVATED, deactivated);
	}

	/**
	 * Get the deactivated status of the DID that kept in this metadata
	 * object.
	 *
	 * @return true if DID is deactivated, otherwise false
	 */
	public boolean isDeactivated( ) {
		return getBoolean(DEACTIVATED);
	}

	/**
	 * Returns a shallow copy of this instance: the property names and values
	 * themselves are not cloned.
	 *
	 * @return a shallow copy of this object
	 */
	@Override
	public DIDMetadata clone() {
		try {
			return (DIDMetadata)super.clone();
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
				getStore().storeDidMetadata(did, this);
			} catch (DIDStoreException e) {
				throw new UnknownInternalException(e);
			}
		}
	}
}