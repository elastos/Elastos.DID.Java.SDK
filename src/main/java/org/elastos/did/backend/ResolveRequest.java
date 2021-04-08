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

import java.util.ArrayList;
import java.util.List;

import org.elastos.did.DIDEntity;
import org.elastos.did.exception.DIDSyntaxException;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * The abstract super class for all resolve requests. Include:
 * - DIDResolveRequest
 * - CredentialResolveRequest
 * - CredentialListRequest
 *
 * @param <T> the type of the class modeled by this ResolveRequest object
 * @param <P> the class of the request parameters
 */
@JsonPropertyOrder({ ResolveRequest.ID,
	ResolveRequest.METHOD,
	ResolveRequest.PARAMETERS })
public abstract class ResolveRequest<T, P> extends DIDEntity<T> {
	protected static final String ID = "id";
	protected static final String METHOD = "method";
	protected static final String PARAMETERS = "params";

	@JsonProperty(ID)
	private String requestId;
	@JsonProperty(METHOD)
	private String method;
	private P params;

	/**
	 * Construct a ResolveRequest object with the given value.
	 *
	 * @param requestId the unique request id
	 * @param method the resolve method name
	 */
	protected ResolveRequest(String requestId, String method) {
		this.requestId = requestId;
		this.method = method;
	}

	/**
	 * Get the unique request id.
	 *
	 * @return the request id
	 */
	public String getRequestId() {
		return requestId;
	}

	/**
	 * Get the resolve method name.
	 *
	 * @return the resolve method name
	 */
	public String getMethod() {
		return method;
	}

	/**
	 * Set the request parameters object.
	 *
	 * @param params the request parameters
	 */
	protected void setParameters(P params) {
		this.params = params;
	}

	/**
	 * Get the request parameters object.
	 *
	 * @return the request parameters
	 */
	protected P getParameters() {
		return params;
	}

	/**
	 * Map an array(single element) of the parameter objects to parameter object.
	 *
	 * <p>
	 * NOTICE: this is required by the Ethereum RPC call schema.
	 * </p>
	 *
	 * @param params an array of the parameter objects
	 */
	@JsonSetter(PARAMETERS)
	private void _setParameters(List<P> params) {
		this.params = (params == null || params.isEmpty()) ? null : params.get(0);
	}

	/**
	 * Map the parameter object to an single element array.
	 *
	 * <p>
	 * NOTICE: this is required by the Ethereum RPC call schema.
	 * </p>
	 *
	 * @return an array(single element) of the parameter objects
	 */
	@JsonGetter(PARAMETERS)
	private List<P> _getParameters() {
		if (params != null) {
			List<P> ret = new ArrayList<P>(1);
			ret.add(params);
			return ret;
		} else {
			return null;
		}
	}

	/**
	 * Returns a hash code for this resolve request object.
	 *
	 * @return a hash code for this request
	 */
	@Override
	public int hashCode() {
		return method.hashCode() + params.hashCode();
	}

	/**
	 * Indicates whether the other resolve request object is "equal to" this
	 * one.
	 *
	 * The equals method implements an equivalence relation on non-null
	 * object references: method name and the parameters are both equals.
	 */
	@Override
	public boolean equals(Object o) {
		if (!(o instanceof ResolveRequest<?, ?>))
			return false;

		ResolveRequest<?, ?> rr = (ResolveRequest<?, ?>)o;

		if (!method.equals(rr.method))
			return false;

		return params.equals(rr.params);
	}

	/**
	 * Parse a resolve request from JsonNode object.
	 *
	 * @param <T> the class type of the resolve request
	 * @param content a JsonNode object that contains a resolve request
	 * @param clazz the class of the resolve request
	 * @return the parsed resolve request object
	 *
	 * @throws DIDSyntaxException if error when parse the resolve request
	 */
	protected static<T extends DIDEntity<?>> T parse(JsonNode content, Class<T> clazz)
			throws DIDSyntaxException {
		return DIDEntity.parse(content, clazz);
	}
}
