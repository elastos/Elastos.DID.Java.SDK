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

@JsonPropertyOrder({ "id", "jsonrpc", "result", "error" })
@JsonInclude(Include.NON_NULL)
public class ResolveResponse extends DIDObject<ResolveResponse> {
	private static final String JSON_RPC_VERSION = "2.0";

	@JsonProperty("id")
	private String id;
	@JsonProperty("jsonrpc")
	private String jsonRpcVersion;
	@JsonProperty("result")
	private ResolveResult result;
	@JsonProperty("error")
	private JsonRpcError error;

	@JsonPropertyOrder({ "code", "message", "data" })
	public static class JsonRpcError {
		@JsonProperty("code")
		private int code;
		@JsonProperty("message")
		private String message;
		@JsonProperty("data")
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

	@JsonCreator
	protected ResolveResponse() {
	}

	protected ResolveResponse(String id, ResolveResult result) {
		this.id = id;
		this.jsonRpcVersion = JSON_RPC_VERSION;
		this.result = result;
	}

	protected ResolveResponse(String id, int code, String message) {
		this.id = id;
		this.jsonRpcVersion = JSON_RPC_VERSION;
		this.error = new JsonRpcError();
	}

	public String getId() {
		return id;
	}

	public ResolveResult getResult() {
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
