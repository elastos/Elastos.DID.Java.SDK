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

package org.elastos.did.backend;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.elastos.did.DIDURL;
import org.elastos.did.exception.MalformedIDChainTransactionException;
import org.elastos.did.exception.MalformedResolveResultException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({ CredentialBiography.ID,
	CredentialBiography.STATUS,
	CredentialBiography.TRANSACTION })
public class CredentialBiography extends ResolveResult<CredentialBiography> {
	protected final static String ID = "id";
	protected final static String STATUS = "status";
	protected final static String TRANSACTION = "transaction";

	/**
	 * The credential is valid.
	 */
	public static final int STATUS_VALID = 0;
	/**
	 * The credential is expired.
	 */
	public static final int STATUS_EXPIRED = 1;
	/**
	 * The credential is revoked.
	 */
	public static final int STATUS_REVOKED = 2;
	/**
	 * The credential is not published.
	 */
	public static final int STATUS_NOT_FOUND = 3;


	@JsonProperty(ID)
	private DIDURL id;
	@JsonProperty(STATUS)
	private int status;
	@JsonProperty(TRANSACTION)
	private List<CredentialTransaction> txs;

	/**
	 * Constructs the Resolve Result with the given value.
	 *
	 * @param did the specified DID
	 * @param status the DID's status
	 */
	@JsonCreator
	protected CredentialBiography(@JsonProperty(value = ID, required = true)DIDURL id,
			@JsonProperty(value = STATUS, required = true) int status) {
		this.id = id;
		this.status = status;
	}

	protected CredentialBiography(DIDURL id) {
		this.id = id;
	}

	public DIDURL getId() {
		return id;
	}

	protected void setStatus(int status) {
		this.status = status;
	}

	public int getStatus() {
		return status;
	}

	public int getTransactionCount() {
		return txs != null ? txs.size() : 0;
	}

	/**
	 * Get the index transaction content.
	 *
	 * @param index the index
	 * @return the index CredentialTransaction content
	 */
	public CredentialTransaction getTransaction(int index) {
		return txs != null ? txs.get(index) : null;
	}

	public List<CredentialTransaction> getAllTransactions() {
		return txs != null ? Collections.unmodifiableList(txs) : null;
	}

	/**
	 * Add transaction infomation into IDChain Transaction.
	 * @param tx the DIDTransaction object
	 */
	protected synchronized void addTransaction(CredentialTransaction tx) {
		if (txs == null)
			txs = new LinkedList<CredentialTransaction>();

		txs.add(tx);
	}

	@Override
	protected void sanitize() throws MalformedResolveResultException {
		if (id == null)
			throw new MalformedResolveResultException("Missing id");

		if (status < STATUS_VALID || status > STATUS_NOT_FOUND)
			throw new MalformedResolveResultException("Unknown status");

		if (status != STATUS_NOT_FOUND) {
			if (txs == null || txs.size() == 0)
				throw new MalformedResolveResultException("Missing transaction");

			try {
				for (CredentialTransaction tx : txs)
					tx.sanitize();
			} catch (MalformedIDChainTransactionException e) {
				throw new MalformedResolveResultException("Invalid transaction", e);
			}
		} else {
			if (txs != null)
				throw new MalformedResolveResultException("Should not include transaction");
		}
	}
}
