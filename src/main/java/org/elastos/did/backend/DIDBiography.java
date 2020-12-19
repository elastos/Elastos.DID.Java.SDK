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

import org.elastos.did.DID;
import org.elastos.did.exception.MalformedIDChainTransactionException;
import org.elastos.did.exception.MalformedResolveResultException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * The class records the resolved content.
 */
@JsonPropertyOrder({ DIDBiography.DID,
	DIDBiography.STATUS,
	DIDBiography.TRANSACTION })
@JsonInclude(Include.NON_NULL)
public class DIDBiography extends ResolveResult<DIDBiography> {
	protected final static String DID = "did";
	protected final static String STATUS = "status";
	protected final static String TRANSACTION = "transaction";

	/**
	 * The DID is valid.
	 */
	public static final int STATUS_VALID = 0;
	/**
	 * The DID is expired.
	 */
	public static final int STATUS_EXPIRED = 1;
	/**
	 * The DID is deactivated.
	 */
	public static final int STATUS_DEACTIVATED = 2;
	/**
	 * The DID is not published.
	 */
	public static final int STATUS_NOT_FOUND = 3;


	@JsonProperty(DID)
	private DID did;
	@JsonProperty(STATUS)
	private int status;
	@JsonProperty(TRANSACTION)
	private List<DIDTransaction> txs;

	/**
	 * Constructs the Resolve Result with the given value.
	 *
	 * @param did the specified DID
	 * @param status the DID's status
	 */
	@JsonCreator
	protected DIDBiography(@JsonProperty(value = DID, required = true)DID did,
			@JsonProperty(value = STATUS, required = true) int status) {
		this.did = did;
		this.status = status;
	}

	protected DIDBiography(DID did) {
		this.did = did;
	}

	public DID getDid() {
		return did;
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
	 * @return the index DIDTransaction content
	 */
	public DIDTransaction getTransaction(int index) {
		return txs != null ? txs.get(index) : null;
	}

	public List<DIDTransaction> getAllTransactions() {
		return txs != null ? Collections.unmodifiableList(txs) : null;
	}

	/**
	 * Add transaction infomation into IDChain Transaction.
	 * @param tx the DIDTransaction object
	 */
	protected synchronized void addTransaction(DIDTransaction tx) {
		if (txs == null)
			txs = new LinkedList<DIDTransaction>();

		txs.add(tx);
	}

	@Override
	protected void sanitize() throws MalformedResolveResultException {
		if (did == null)
			throw new MalformedResolveResultException("Missing did");

		if (status < STATUS_VALID || status > STATUS_NOT_FOUND)
			throw new MalformedResolveResultException("Unknown status");

		if (status != STATUS_NOT_FOUND) {
			if (txs == null || txs.size() == 0)
				throw new MalformedResolveResultException("Missing transaction");

			try {
				for (DIDTransaction tx : txs)
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
