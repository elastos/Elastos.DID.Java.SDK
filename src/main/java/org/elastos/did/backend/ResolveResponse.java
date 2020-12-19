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

import org.elastos.did.DIDObject;
import org.elastos.did.exception.MalformedResolveResultException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({ ResolveResponse.ID,
	ResolveResponse.JSON_RPC,
	ResolveResponse.RESULT,
	ResolveResponse.ERROR })
@JsonInclude(Include.NON_NULL)
public abstract class ResolveResponse<T, R extends ResolveResult<R>> extends DIDObject<T> {
	private static final String JSON_RPC_VERSION = "2.0";

	protected static final String ID = "id";
	protected static final String JSON_RPC = "jsonrpc";
	protected static final String RESULT = "result";
	protected static final String ERROR = "error";
	protected static final String ERROR_CODE = "code";
	protected static final String ERROR_MESSAGE = "message";
	protected static final String ERROR_DATA = "data";

	@JsonProperty(ID)
	private String responseId;
	@JsonProperty(JSON_RPC)
	private String jsonRpcVersion;
	@JsonProperty(RESULT)
	private R result;
	@JsonProperty(ERROR)
	private JsonRpcError error;

	@JsonPropertyOrder({ ERROR_CODE, ERROR_MESSAGE, ERROR_DATA })
	public static class JsonRpcError {
		@JsonProperty(ERROR_CODE)
		private int code;
		@JsonProperty(ERROR_MESSAGE)
		private String message;
		@JsonProperty(ERROR_DATA)
		private String data;

		@JsonCreator
		protected JsonRpcError() {}

		protected JsonRpcError(int code, String message) {
			this.code = code;
			this.message = message;
		}

		public int getCode() {
			return code;
		}

		public String getMessage() {
			return message;
		}

		public String getData() {
			return data;
		}
	}

	protected ResolveResponse() {
	}

	protected ResolveResponse(String responseId, R result) {
		this.responseId = responseId;
		this.jsonRpcVersion = JSON_RPC_VERSION;
		this.result = result;
	}

	protected ResolveResponse(String responseId, int code, String message) {
		this.responseId = responseId;
		this.jsonRpcVersion = JSON_RPC_VERSION;
		this.error = new JsonRpcError();
	}

	public String getResponseId() {
		return responseId;
	}

	public R getResult() {
		return result;
	}

	public int getErrorCode() {
		return error.getCode();
	}

	public String getErrorMessage() {
		return error.getMessage();
	}

	@Override
	protected void sanitize() throws MalformedResolveResultException {
		if (jsonRpcVersion == null || !jsonRpcVersion.equals(JSON_RPC_VERSION))
			throw new MalformedResolveResultException("Invalid JsonRPC version");

		if (result == null && error == null)
			throw new MalformedResolveResultException("Missing result or error");

		if (result != null)
			result.sanitize();
	}

}
