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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The interface for Credential's meta data(include alias name, last modified time for Credential
 * and user's extra element).
 */
/**
 * The class defines the implement of Credential Meta data.
 */
public class CredentialMetadata extends AbstractMetadata implements Cloneable {
	private final static String TXID = "txid";
	private final static String PUBLISHED = "published";
	private final static String REVOKED = "revoked";

	private DIDURL id;

	private static final Logger log = LoggerFactory.getLogger(CredentialMetadata.class);

	/**
	 *  The default constructor for JSON deserialize creator.
	 */
	protected CredentialMetadata() {
		this(null);
	}

	/**
	 * Construct the empty CredentialMetadataImpl.
	 */
	protected CredentialMetadata(DIDURL id) {
		this(id, null);
	}

	/**
	 * Construct the CredentialMetadataImpl with the given store.
	 *
	 * @param store the specified DIDStore
	 */
	protected CredentialMetadata(DIDURL id, DIDStore store) {
		super(store);
		this.id = id;
	}

	protected void setId(DIDURL id) {
		this.id = id;
	}

	/**
	 * Set transaction id for CredentialMetadata.
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
	 * Set published time for CredentialMetadata.
	 *
	 * @param timestamp the time published
	 */
	protected void setPublished(Date timestamp) {
		checkArgument(timestamp != null, "Invalid timestamp");

		put(PUBLISHED, timestamp);
	}

	/**
	 * Get the time of the latest declare transaction.
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
	 * Set revoked status into CredentialMetadata.
	 *
	 * @param revoked the revocation status
	 */
	protected void setRevoked(boolean revoked) {
		put(REVOKED, revoked);
	}

	/**
	 * the DID revoked status.
	 *
	 * @return the returned value is true if the did is revoked.
	 *         the returned value is false if the did is not revoked.
	 */
	public boolean isRevoked( ) {
		return getBoolean(REVOKED);
	}

    /**
     * Returns a shallow copy of this instance: the keys and values themselves
     * are not cloned.
     *
     * @return a shallow copy of this object
     */
	@Override
	public CredentialMetadata clone() {
		try {
			return (CredentialMetadata)super.clone();
		} catch (CloneNotSupportedException ignore) {
			ignore.printStackTrace();
			return null;
		}
    }

	@Override
	protected void save() {
		if (attachedStore()) {
			try {
				getStore().storeCredentialMetadata(id, this);
			} catch (DIDStoreException ignore) {
				log.error("INTERNAL - error store metadata for credential {}", id);
			}
		}
	}
}

