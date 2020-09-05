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

import java.util.Date;

public interface DIDTransaction {
	/**
	 * Get owner of DID transaction.
	 *
	 * @return the owner DID
	 */
	public DID getDid();

	/**
	 * Get id of DID transaction.
	 *
	 * @return the transaction id string
	 */
	public String getTransactionId();

	/**
	 * Get published time of DID transaction.
	 *
	 * @return the time
	 */
	public Date getTimestamp();

	/**
	 * Get operation string of DID transaction.
	 *
	 * @return the operation string
	 */
	public String getOperation();

	/**
	 * Get DID Document from DID transaction.
	 *
	 * @return the DID Document object
	 */
	public DIDDocument getDocument();
}
