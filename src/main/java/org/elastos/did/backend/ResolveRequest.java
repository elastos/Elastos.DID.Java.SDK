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
import org.elastos.did.DIDObject;
import org.elastos.did.exception.MalformedDIDException;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({ "id", "method", "params" })
public class ResolveRequest extends DIDObject<ResolveRequest> {
	public static final String METHOD_RESOLVE_DID = "resolvedid";

	@JsonProperty("id")
	private String id;
	@JsonProperty("method")
	private String method;
	@JsonProperty("params")
	private Parameters params;

	@JsonPropertyOrder({ "did", "all" })
	protected static class Parameters {
		@JsonProperty("did")
		private DID did;
		@JsonProperty("all")
		private boolean all;
	}

	public ResolveRequest(String id, String method) {
		this.id = id;
		this.method = method;
		this.params = new Parameters();
	}

	public String getId() {
		return id;
	}

	public String getMethod() {
		return method;
	}

	public void setParameter(DID did, boolean all) {
		this.params.did = did;
		this.params.all = all;

	}

	public void setParameter(String did, boolean all) {
		try {
			setParameter(new DID(did), all);
		} catch (MalformedDIDException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public DID getDid() {
		return params.did;
	}

	public boolean isResolveAll() {
		return params.all;
	}
}
