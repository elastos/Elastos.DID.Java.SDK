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
 * Credential list request object.
 */
public class CredentialListRequest extends ResolveRequest<CredentialListRequest, CredentialListRequest.Parameters> {
	protected static final String PARAMETER_DID = "did";
	protected static final String PARAMETER_SKIP = "skip";
	protected static final String PARAMETER_LIMIT = "limit";

	public static final String METHOD_NAME = "did_listCredentials";

	/**
	 * The parameters object for credential list request.
	 */
	protected static class Parameters {
		@JsonProperty(PARAMETER_DID)
		private DID did;

		@JsonProperty(PARAMETER_SKIP)
		@JsonInclude(Include.NON_DEFAULT)
		private int skip;

		@JsonProperty(PARAMETER_LIMIT)
		@JsonInclude(Include.NON_DEFAULT)
		private int limit;

		public Parameters(DID did, int skip, int limit) {
			this.did = did;
			this.skip = skip;
			this.limit = limit;
		}

		public Parameters(DID did, int limit) {
			this(did, 0, limit);
		}

		@JsonCreator
		public Parameters(@JsonProperty(value = PARAMETER_DID, required = true)DID did) {
			this(did, 0, 0);
		}

		@Override
		public int hashCode() {
			int hash = did.hashCode();
			hash += Integer.hashCode(skip);
			hash += Integer.hashCode(limit);
			return hash;
		}

		@Override
		public boolean equals(Object o) {
			if (!(o instanceof Parameters))
				return false;

			Parameters p = (Parameters)o;

			if (!did.equals(p.did))
				return false;

			if (skip != p.skip)
				return false;

			return limit == p.limit;
		}
	}

	/**
	 * Create a credential list request with the given request id.
	 *
	 * @param requestId a request id string
	 */
	@JsonCreator
	public CredentialListRequest(@JsonProperty(value = ID)String requestId) {
		super(requestId, METHOD_NAME);
	}

	/**
	 * Set parameters for the list request.
	 *
	 * @param did the target DID
	 * @param skip set to skip N credentials ahead in this request
	 * 		  (useful for pagination).
	 * @param limit set the limit of credentials returned in the request
	 * 		  (useful for pagination).
	 */
	public void setParameters(DID did, int skip, int limit) {
		setParameters(new Parameters(did, skip, limit));
	}

	/**
	 * Set parameters for the list request. No skip in this request.
	 *
	 * @param did the target DID
	 * @param limit set the limit of credentials returned in the request
	 * 		  (useful for pagination).
	 */
	public void setParameters(DID did, int limit) {
		setParameters(new Parameters(did, limit));
	}

	/**
	 * Set parameters for the list request. No skip and use the resolver's
	 * default limits in this request,
	 *
	 * @param did the target DID
	 */
	public void setParameters(DID did) {
		setParameters(new Parameters(did));
	}

	/**
	 * Set parameters for the list request.
	 *
	 * @param did the target DID
	 * @param skip set to skip N credentials ahead in this request
	 * 		  (useful for pagination).
	 * @param limit set the limit of credentials returned in the request
	 * 		  (useful for pagination).
	 */
	public void setParameters(String did, int skip, int limit) {
		setParameters(DID.valueOf(did), skip, limit);
	}

	/**
	 * Set parameters for the list request. No skip in this request.
	 *
	 * @param did the target DID
	 * @param limit set the limit of credentials returned in the request
	 * 		  (useful for pagination).
	 */
	public void setParameters(String did, int limit) {
		setParameters(DID.valueOf(did), limit);
	}

	/**
	 * Set parameters for the list request. No skip and use the resolver's
	 * default limits in this request,
	 *
	 * @param did the target DID
	 */
	public void setParameters(String did) {
		setParameters(DID.valueOf(did));
	}

	/**
	 * Get the target DID of this request.
	 *
	 * @return the target DID
	 */
	public DID getDid() {
		return getParameters().did;
	}

	/**
	 * Get the skip number of this request.
	 *
	 * @return the skip number, 0 if not set
	 */
	public int getSkip() {
		return getParameters().skip;
	}

	/**
	 * Get the limit number of this request.
	 *
	 * @return the limit number, 0 if not set
	 */
	public int getLimit() {
		return getParameters().limit;
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
		builder.setPath("/credentials");
		builder.setQueryParameter(PARAMETER_SKIP, Integer.toString(getParameters().skip));
		builder.setQueryParameter(PARAMETER_LIMIT, Integer.toString(getParameters().limit));

		return builder.build().toString();
	}
}
