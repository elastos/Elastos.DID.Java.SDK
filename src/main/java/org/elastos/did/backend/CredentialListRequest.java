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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

public class CredentialListRequest extends ResolveRequest<CredentialListRequest, CredentialListRequest.Parameters> {
	protected static final String PARAMETER_DID = "did";
	protected static final String PARAMETER_SKIP = "skip";
	protected static final String PARAMETER_LIMIT = "limit";

	protected static final String METHOD_NAME = "listcredential";

	protected static class Parameters {
		@JsonProperty(PARAMETER_DID)
		private DID did;

		@JsonProperty(PARAMETER_SKIP)
		@JsonInclude(Include.NON_NULL)
		private Integer skip;

		@JsonProperty(PARAMETER_SKIP)
		@JsonInclude(Include.NON_NULL)
		private Integer limit;

		public Parameters(DID did, Integer skip, Integer limit) {
			this.did = did;
			this.skip = skip;
			this.limit = limit;
		}

		public Parameters(DID did, int limit) {
			this(did, null, limit);
		}

		@JsonCreator
		public Parameters(@JsonProperty(value = PARAMETER_DID, required = true)DID did) {
			this(did, null, null);
		}
	}

	@JsonCreator
	public CredentialListRequest(@JsonProperty(value = ID)String requestId) {
		super(requestId, METHOD_NAME);
	}

	public void setParameters(DID did, int skip, int limit) {
		setParameters(new Parameters(did, skip, limit));
	}

	public void setParameters(DID did, int limit) {
		setParameters(new Parameters(did, limit));
	}

	public void setParameters(DID did) {
		setParameters(new Parameters(did));
	}

	public void setParameters(String did, int skip, int limit) {
		try {
			setParameters(new DID(did), skip, limit);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public void setParameters(String did, int limit) {
		try {
			setParameters(new DID(did), limit);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public void setParameters(String did) {
		try {
			setParameters(new DID(did));
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public DID getDid() {
		return getParameters().did;
	}

	public int getSkip() {
		return getParameters().skip == null ? 0 : getParameters().skip;
	}

	public int getLimit() {
		return getParameters().limit == null ? 0 : getParameters().limit;
	}
}
