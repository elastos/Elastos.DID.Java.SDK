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

import java.io.InputStream;

import org.elastos.did.exception.DIDResolveException;

/**
 * The interface for DIDResolver to support method to resolve did document from chain.
 */
public interface DIDResolver {
	/**
	 * Get the newest DID Document from chain.
	 *
	 * @param requestId the request identifier by user defined
	 * @param did the did string
	 * @param all all = true, get all did transaction;
	 *            all = false, get the lastest did transaction.
	 * @return the resolve result
	 * @throws DIDResolveException resolve did failed.
	 */
	public InputStream resolveDid(String requestId, String did, boolean all)
			throws DIDResolveException;

	public InputStream resolveCredential(String requestId, String id)
			throws DIDResolveException;

	public InputStream listCredentials(String requestId, String did, int skip, int limit)
			throws DIDResolveException;

	public InputStream resolveCredentialRevocation(String requestId, String id, String signer)
			throws DIDResolveException;

}
