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

/**
 * The interface for DIDHistroy to store all did transactions from chain.
 */
public interface DIDHistory {
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

	/**
	 * Get owner of DID resolved history.
	 *
	 * @return the owner object
	 */
	public DID getDid();

	/**
	 * Get DID status.
	 *
	 * @return the status code
	 */
	public int getStatus();

	/**
	 * Get all Id transactions about the specified DID.
	 *
	 * @return the did transaction array
	 */
	public List<DIDTransaction> getAllTransactions();

	/**
	 * Get the count of transactions.
	 *
	 * @return the count
	 */
	public int getTransactionCount();
}
