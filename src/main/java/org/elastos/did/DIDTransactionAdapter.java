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

import org.elastos.did.exception.DIDTransactionException;

/**
 * An interface for publishing the DID Entities.
 *
 * <p>
 * This adapter should support both DID and credential publishing.
 * When the DID SDK needs publish DID or credential transactions, the SDK
 * will call this interface to publish the transaction.
 * </p>
 */
public interface DIDTransactionAdapter {
	/**
	 * Create and publish a ID chain transaction with the given
	 * ID request as payload and the memo.
	 *
	 * @param payload a string representation of the ID request
	 * @param memo a memorandum string
	 * @throws DIDTransactionException if an error occurred when publishing the transaction
	 */
	public void createIdTransaction(String payload, String memo)
		throws DIDTransactionException;
}
