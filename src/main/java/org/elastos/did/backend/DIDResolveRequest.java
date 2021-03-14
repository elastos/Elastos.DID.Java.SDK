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
import org.elastos.did.DIDURL;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * DID(document) resolve request object.
 */
public class DIDResolveRequest extends ResolveRequest<DIDResolveRequest, DIDResolveRequest.Parameters> {
	protected static final String PARAMETER_DID = "did";
	protected static final String PARAMETER_ALL = "all";

	public static final String METHOD_NAME = "resolvedid";

	/**
	 * The parameters for DID resolve request.
	 */
	protected static class Parameters {
		@JsonProperty(PARAMETER_DID)
		private DID did;

		@JsonProperty(PARAMETER_ALL)
		@JsonInclude(Include.NON_DEFAULT)
		private boolean all;

		public Parameters(DID did, boolean all) {
			this.did = did;
			this.all = all;
		}

		@JsonCreator
		public Parameters(@JsonProperty(value = PARAMETER_DID, required = true)DID did) {
			this(did, false);
		}

		@Override
		public int hashCode() {
			int hash = did.hashCode();
			hash += Boolean.hashCode(all);
			return hash;
		}

		@Override
		public boolean equals(Object o) {
			if (!(o instanceof Parameters))
				return false;

			Parameters p = (Parameters)o;

			if (!did.equals(p.did))
				return false;

			return all == p.all;
		}

	}

	/**
	 * Create a DID resolve request with the given request id.
	 *
	 * @param requestId a request id string
	 */
	@JsonCreator
	public DIDResolveRequest(@JsonProperty(value = ID)String requestId) {
		super(requestId, METHOD_NAME);
	}

	/**
	 * Set parameters for the resolve request.
	 *
	 * @param did the target did
	 * @param all resolve all did transactions
	 */
	public void setParameters(DID did, boolean all) {
		setParameters(new Parameters(did, all));
	}

	/**
	 * Set parameters for the resolve request.
	 *
	 * @param did the target did
	 * @param all resolve all did transactions
	 */
	public void setParameters(String did, boolean all) {
		setParameters(DID.valueOf(did), all);
	}

	/**
	 * Get the target DID.
	 *
	 * @return the target DID
	 */
	public DID getDid() {
		return getParameters().did;
	}

	/**
	 * Returns if this request resolve all transactions for the target DID.
	 *
	 * @return ture if resolve all, otherwise false
	 */
	public boolean isResolveAll() {
		return getParameters().all;
	}

	/**
	 * Constructs a string representation of this request. The string using
	 * DIDURL format.
	 *
	 * @return a string representation of this object.
	 */
	@Override
	public String toString() {
		DIDURL.Builder builder = new DIDURL.Builder(getParameters().did);
		builder.setQueryParameter(PARAMETER_ALL, String.valueOf(getParameters().all));
		return builder.build().toString();
	}
}
