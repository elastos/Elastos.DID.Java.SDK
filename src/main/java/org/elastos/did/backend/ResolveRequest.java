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

import java.util.HashMap;
import java.util.Map;

import org.elastos.did.DIDObject;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({ ResolveRequest.ID,
	ResolveRequest.METHOD,
	ResolveRequest.PARAMETERS })
public abstract class ResolveRequest<T> extends DIDObject<T> {
	protected static final String ID = "id";
	protected static final String METHOD = "method";
	protected static final String PARAMETERS = "params";

	@JsonProperty(ID)
	private String requestId;
	@JsonProperty(METHOD)
	private String method;
	@JsonProperty(PARAMETERS)
	private Map<String, Object> params;

	protected ResolveRequest(String requestId, String method) {
		this.requestId = requestId;
		this.method = method;
		this.params = new HashMap<String, Object>();
	}

	public String getRequestId() {
		return requestId;
	}

	public String getMethod() {
		return method;
	}

	protected void setParameter(String param, Object value) {
		params.put(param, value);

	}

	protected Object getParameter(String param) {
		return params.get(param);
	}

	protected Object getParameter(String param, Object defaultValue) {
		return params.getOrDefault(param, defaultValue);
	}
}
