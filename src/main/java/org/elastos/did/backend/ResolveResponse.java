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

import org.elastos.did.DIDEntity;
import org.elastos.did.exception.MalformedResolveResponseException;
import org.elastos.did.exception.MalformedResolveResultException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * The abstract super class for all resolve response. Include:
 * - DIDResolveResponse
 * - CredentialResolveResponse
 * - CredentialListResponse
 *
 * @param <T> the type of the class modeled by this ResolveResponse object
 * @param <R> the class of the request result
 */
@JsonPropertyOrder({ ResolveResponse.ID,
	ResolveResponse.JSON_RPC,
	ResolveResponse.RESULT,
	ResolveResponse.ERROR })
@JsonInclude(Include.NON_NULL)
public abstract class ResolveResponse<T, R extends ResolveResult<R>> extends DIDEntity<T> {
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
	@JsonInclude(Include.NON_NULL)
	private JsonRpcError error;

	/**
	 * JsonRPC error object.
	 */
	@JsonPropertyOrder({ ERROR_CODE, ERROR_MESSAGE, ERROR_DATA })
	protected static class JsonRpcError {
		@JsonProperty(ERROR_CODE)
		private int code;
		@JsonProperty(ERROR_MESSAGE)
		private String message;
		@JsonProperty(ERROR_DATA)
		private String data;

		/**
		 * The default constructor.
		 */
		@JsonCreator
		protected JsonRpcError() {}

		/**
		 * Construct a JsonRpcError object with the give error information.
		 *
		 * @param code the error code
		 * @param message the detail error message
		 */
		protected JsonRpcError(int code, String message) {
			this.code = code;
			this.message = message;
		}

		/**
		 * Get the error code.
		 *
		 * @return the error code
		 */
		public int getCode() {
			return code;
		}

		/**
		 * Get the error message.
		 *
		 * @return the error message.
		 */
		public String getMessage() {
			return message;
		}

		/**
		 * Get the error related data information. Return null if not set.
		 *
		 * @return the error data
		 */
		public String getData() {
			return data;
		}
	}

	/**
	 * The default constructor.
	 */
	protected ResolveResponse() {
	}

	/**
	 * Create a success ResolveResponse object with the specific result object.
	 *
	 * @param responseId the response id, normally same with the related request id
	 * @param result a resolve result object
	 */
	protected ResolveResponse(String responseId, R result) {
		this.responseId = responseId;
		this.jsonRpcVersion = JSON_RPC_VERSION;
		this.result = result;
	}

	/**
	 * Create an error ResolveResponse object.
	 *
	 * @param responseId the response id, normally same with the related request id
	 * @param code an error code
	 * @param message an error message, could be null
	 */
	protected ResolveResponse(String responseId, int code, String message) {
		this.responseId = responseId;
		this.jsonRpcVersion = JSON_RPC_VERSION;
		this.error = new JsonRpcError();
	}

	/**
	 * Get the response id.
	 *
	 * @return the response id
	 */
	public String getResponseId() {
		return responseId;
	}

	/**
	 * Get the resolve result object.
	 * @return the resolve result object inside this response
	 */
	public R getResult() {
		return result;
	}

	/**
	 * Get the error code. 0 if the response is a success response,
	 * or an error number if the response is an error response.
	 *
	 * @return the error code, 0 means no error
	 */
	public int getErrorCode() {
		return error.getCode();
	}

	/**
	 * Get the error message. null if the response is a success response,
	 * or an error message if the response is an error response with message.
	 *
	 * @return the error message
	 */
	public String getErrorMessage() {
		return error.getMessage();
	}

	/**
	 * Post sanitize routine after deserialization.
	 *
	 * @throws MalformedResolveResponseException if the ResolveResponse
	 * 		   object is invalid
	 */
	@Override
	protected void sanitize() throws MalformedResolveResponseException {
		if (jsonRpcVersion == null || !jsonRpcVersion.equals(JSON_RPC_VERSION))
			throw new MalformedResolveResponseException("Invalid JsonRPC version");

		if (result == null && error == null)
			throw new MalformedResolveResponseException("Missing result or error");

		if (result != null) {
			try {
				result.sanitize();
			} catch (MalformedResolveResultException e) {
				throw new MalformedResolveResponseException("Invalid result", e);
			}
		}
	}
}
