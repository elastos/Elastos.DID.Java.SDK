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

public class CredentialResolveRequest extends ResolveRequest<CredentialResolveRequest, CredentialResolveRequest.Parameters> {
	protected static final String PARAMETER_ID = "id";
	protected static final String PARAMETER_ISSUER = "issuer";

	public static final String METHOD_NAME = "resolvecredential";

	protected static class Parameters {
		@JsonProperty(PARAMETER_ID)
		private DIDURL id;
		@JsonProperty(PARAMETER_ISSUER)
		@JsonInclude(Include.NON_NULL)
		private DID issuer;

		@JsonCreator
		public Parameters(@JsonProperty(value = PARAMETER_ID, required = true)DIDURL id) {
			this(id, null);
		}

		public Parameters(DIDURL id, DID issuer) {
			this.id = id;
			this.issuer = issuer;
		}

		@Override
		public int hashCode() {
			int hash = id.hashCode();

			if (issuer != null)
				hash += issuer.hashCode();

			return hash;
		}

		@Override
		public boolean equals(Object o) {
			if (!(o instanceof Parameters))
				return false;

			Parameters p = (Parameters)o;

			if (!id.equals(p.id))
				return false;

			DID lIssuer = this.issuer != null ? this.issuer : this.id.getDid();
			DID rIssuer = p.issuer != null ? p.issuer : p.id.getDid();

			return lIssuer.equals(rIssuer);
		}
	}

	@JsonCreator
	public CredentialResolveRequest(@JsonProperty(value = ID)String requestId) {
		super(requestId, METHOD_NAME);
	}

	public void setParameters(DIDURL id, DID issuer) {
		setParameters(new Parameters(id, issuer));
	}

	public void setParameters(DIDURL id) {
		setParameters(id, null);
	}

	public void setParameters(String id, String issuer) {
		setParameters(DIDURL.valueOf(id), DID.valueOf(issuer));
	}

	public void setParameters(String id) {
		setParameters(id, null);
	}

	public DIDURL getId() {
		return getParameters().id;
	}

	public DID getIssuer() {
		return getParameters().issuer;
	}

	@Override
	public String toString() {
		DIDURL.Builder builder = new DIDURL.Builder(getParameters().id);
		if (getParameters().issuer != null)
			builder.setQueryParameter(PARAMETER_ISSUER, getParameters().issuer.toString());

		return builder.build().toString();
	}
}
