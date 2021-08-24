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

import org.elastos.did.DIDURL;

import com.fasterxml.jackson.annotation.JsonCreator;

/**
 * The credential transaction object for VerifiableCredential's declare and
 * revoke operations.
 */
public class CredentialTransaction extends IDTransaction<CredentialTransaction, CredentialRequest> {
	/**
	 * Default constructor.
	 */
	@JsonCreator
	protected CredentialTransaction() {}

	/**
	 * Create a CredentialTransaction object with the given value.
	 *
	 * @param txid the transaction id
	 * @param timestamp the time stamp
	 * @param request the CredentialRequest object
	 */
	protected CredentialTransaction(String txid, Date timestamp, CredentialRequest request) {
		super(txid, timestamp, request);
	}

	/**
	 * Get the target id of the credential operation contained in
	 * this DID transaction.
	 *
	 * @return the target credential's id
	 */
	public DIDURL getId() {
		return getRequest().getCredentialId();
	}
}
