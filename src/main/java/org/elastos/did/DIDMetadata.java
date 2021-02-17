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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The class defines the implement of DID Metadata.
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

	private static final Logger log = LoggerFactory.getLogger(DIDMetadata.class);

	/**
	 *  The default constructor for JSON deserialize creator.
	 */
	protected DIDMetadata() {
		this(null);
	}

	/**
	 * Constructs the empty DIDMetadataImpl.
	 */
	protected DIDMetadata(DID did) {
		this(did, null);
	}

	/**
	 * Constructs the empty DIDMetadataImpl with the given store.
	 *
	 * @param store the specified DIDStore
	 */
	protected DIDMetadata(DID did, DIDStore store) {
		super(store);
		this.did = did;
	}

	protected void setDid(DID did) {
		this.did = did;
	}

	protected void setRootIdentityId(String id) {
		put(ROOT_IDENTITY, id);
	}

	protected String getRootIdentityId() {
		return get(ROOT_IDENTITY);
	}

	protected void setIndex(int index) {
		put(INDEX, index);
	}

	protected int getIndex() {
		return getInteger(INDEX);
	}

	/**
	 * Set transaction id into DIDMetadata.
	 *
	 * @param txid the transaction id string
	 */
	protected void setTransactionId(String txid) {
		put(TXID, txid);
	}

	/**
	 * Get the last transaction id.
	 *
	 * @return the transaction string
	 */
	public String getTransactionId() {
		return get(TXID);
	}

	/**
	 * Set previous signature into DIDMetadata.
	 *
	 * @param signature the signature string
	 */
	protected void setPreviousSignature(String signature) {
		put(PREV_SIGNATURE, signature);
	}

	/**
	 * Get the document signature from the previous transaction.
	 *
	 * @return the signature string
	 */
	public String getPreviousSignature() {
		return get(PREV_SIGNATURE);
	}

	/**
	 * Set signature into DIDMetadata.
	 *
	 * @param signature the signature string
	 */
	protected void setSignature(String signature) {
		put(SIGNATURE, signature);
	}

	/**
	 * Get the document signature from the lastest transaction.
	 *
	 * @return the signature string
	 */
	public String getSignature() {
		return get(SIGNATURE);
	}

	/**
	 * Set published time into DIDMetadata.
	 *
	 * @param timestamp the time published
	 */
	protected void setPublished(Date timestamp) {
		put(PUBLISHED, timestamp);
	}

	/**
	 * Get the time of the lastest published transaction.
	 *
	 * @return the published time
	 */
	public Date getPublished() {
		try {
			return getDate(PUBLISHED);
		} catch (ParseException e) {
			return null;
		}
	}

	/**
	 * Set deactivate status into DIDMetadata.
	 *
	 * @param deactivated the deactivate status
	 */
	protected void setDeactivated(boolean deactivated) {
		put(DEACTIVATED, deactivated);
	}

	/**
	 * the DID deactivated status.
	 *
	 * @return the returned value is true if the did is deactivated.
	 *         the returned value is false if the did is activated.
	 */
	public boolean isDeactivated( ) {
		return getBoolean(DEACTIVATED);
	}

    /**
     * Returns a shallow copy of this instance: the keys and values themselves
     * are not cloned.
     *
     * @return a shallow copy of this object
     */
	@Override
	public DIDMetadata clone() {
		try {
			return (DIDMetadata)super.clone();
		} catch (CloneNotSupportedException ignore) {
			ignore.printStackTrace();
			return null;
		}
    }

	@Override
	protected void save() {
		if (attachedStore()) {
			try {
				getStore().storeDidMetadata(did, this);
			} catch (DIDStoreException ignore) {
				log.error("INTERNAL - error store metadata for DID {}", did);
			}
		}
	}
}