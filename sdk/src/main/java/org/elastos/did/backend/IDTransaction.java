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

import java.util.Date;

import org.elastos.did.DIDEntity;
import org.elastos.did.exception.MalformedIDChainRequestException;
import org.elastos.did.exception.MalformedIDChainTransactionException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * Abstract base class for all ID transactions. This class defines a skeletal
 * data model of ID chain transactions.
 *
 * @param <T> the type of the class modeled by this IDTransaction object
 * @param <R> the type of the request that include in the IDTransaction
 */
@JsonPropertyOrder({ IDTransaction.TXID,
	IDTransaction.TIMESTAMP,
	IDTransaction.OPERATION })
public abstract class IDTransaction<T, R extends IDChainRequest<R>> extends DIDEntity<T> {
	protected final static String TXID = "txid";
	protected final static String TIMESTAMP = "timestamp";
	protected final static String OPERATION = "operation";

	@JsonProperty(TXID)
	private String txId;
	@JsonProperty(TIMESTAMP)
	private Date timestamp;
	@JsonProperty(OPERATION)
	private R request;

	/**
	 * Default constructor.
	 */
	@JsonCreator
	protected IDTransaction() {}

	/**
	 * Create a IDTransaction with the given values.
	 *
	 * @param txid the transaction id
	 * @param timestamp the time stamp of the ID transaction
	 * @param request the IDChainRequest object
	 */
	protected IDTransaction(String txid, Date timestamp, R request) {
		this.txId = txid;
		this.timestamp = timestamp;
		this.request = request;
	}

	/**
	 * Get the transaction id.
	 *
	 * <p>
	 * The transaction id is a unique identifier of the ID transaction.
	 * Normally it a hex encoded string.
	 * </p>
	 *
	 * @return the transaction id
	 */
	public String getTransactionId() {
		return txId;
	}

	/**
	 * Get the time stamp of the transaction in UTC time.
	 *
	 * @return the time stamp
	 */
	public Date getTimestamp() {
		return timestamp;
	}

	/**
	 * Get ID chain request that included in this transaction.
	 *
	 * @return the IDChainRequest object
	 */
	public R getRequest() {
		return request;
	}

	/**
	 * Check the validity of the object and normalize the object after
	 * deserialized the IDTransaction object from JSON.
	 *
	 * @throws MalformedIDChainTransactionException if the object is invalid
	 */
	@Override
	protected void sanitize() throws MalformedIDChainTransactionException {
		if (txId == null || txId.isEmpty())
			throw new MalformedIDChainTransactionException("Missing txid");

		if (timestamp == null)
			throw new MalformedIDChainTransactionException("Missing timestamp");

		if (request == null)
			throw new MalformedIDChainTransactionException("Missing request");

		try {
			request.sanitize();
		} catch (MalformedIDChainRequestException e) {
			throw new MalformedIDChainTransactionException("Invalid request", e);
		}
	}
}
