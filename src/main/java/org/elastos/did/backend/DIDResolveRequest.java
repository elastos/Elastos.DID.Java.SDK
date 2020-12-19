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

import org.elastos.did.DID;
import org.elastos.did.exception.MalformedDIDException;

public class DIDResolveRequest extends ResolveRequest<DIDResolveRequest> {
	protected static final String PARAMETER_DID = "did";
	protected static final String PARAMETER_ALL = "all";

	private static final String METHOD_NAME = "resolvedid";

	public DIDResolveRequest(String id) {
		super(id, METHOD_NAME);
	}

	public void setParameters(DID did, boolean all) {
		setParameter(PARAMETER_DID, did);
		setParameter(PARAMETER_ALL, all);
	}

	public void setParameters(String did, boolean all) {
		try {
			setParameters(new DID(did), all);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public DID getDid() {
		return (DID)getParameter(PARAMETER_DID);
	}

	public boolean isResolveAll() {
		return (Boolean)getParameter(PARAMETER_ALL, false);
	}
}
