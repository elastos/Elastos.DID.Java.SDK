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

public class CredentialListRequest extends ResolveRequest<CredentialListRequest, CredentialListRequest.Parameters> {
	protected static final String PARAMETER_DID = "did";
	protected static final String PARAMETER_SKIP = "skip";
	protected static final String PARAMETER_LIMIT = "limit";

	public static final String METHOD_NAME = "listcredential";

	protected static class Parameters {
		@JsonProperty(PARAMETER_DID)
		private DID did;

		@JsonProperty(PARAMETER_SKIP)
		@JsonInclude(Include.NON_DEFAULT)
		private Integer skip;

		@JsonProperty(PARAMETER_LIMIT)
		@JsonInclude(Include.NON_DEFAULT)
		private Integer limit;

		public Parameters(DID did, int skip, int limit) {
			this.did = did;

			if (skip > 0)
				this.skip = skip;

			if (limit > 0)
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

			if (skip != null)
				hash += skip.hashCode();

			if (limit != null)
				hash += limit.hashCode();

			return hash;
		}

		@Override
		public boolean equals(Object o) {
			if (!(o instanceof Parameters))
				return false;

			Parameters p = (Parameters)o;

			if (!did.equals(p.did))
				return false;

			int lSkip = this.skip == null ? 0 : this.skip.intValue();
			int rSkip = p.skip == null ? 0 : p.skip.intValue();
			if (lSkip != rSkip)
				return false;

			int lLimit = this.limit == null ? 0 : this.limit.intValue();
			int rLimit = p.limit == null ? 0 : p.limit.intValue();
			return lLimit == rLimit;
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
		setParameters(DID.valueOf(did), skip, limit);
	}

	public void setParameters(String did, int limit) {
		setParameters(DID.valueOf(did), limit);
	}

	public void setParameters(String did) {
		setParameters(DID.valueOf(did));
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

	@Override
	public String toString() {
		DIDURL.Builder builder = new DIDURL.Builder(getParameters().did);
		builder.setPath("/credentials");

		builder.setQueryParameter(PARAMETER_SKIP, getParameters().skip == null ?
				"0" : getParameters().skip.toString());

		builder.setQueryParameter(PARAMETER_LIMIT, getParameters().limit == null ?
				"0" : getParameters().limit.toString());

		return builder.build().toString();
	}

}
