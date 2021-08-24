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

import com.fasterxml.jackson.annotation.JsonCreator;

/**
 * DID(document) resolve response object.
 */
public class DIDResolveResponse extends ResolveResponse<DIDResolveResponse, DIDBiography> {
	@JsonCreator
	protected DIDResolveResponse() {
		super();
	}

	/**
	 * Create a success DIDResolveResponse object with the specific result object.
	 *
	 * @param responseId the response id, normally same with the related request id
	 * @param result a DIDBiography object
	 */
	protected DIDResolveResponse(String responseId, DIDBiography result) {
		super(responseId, result);
	}

	/**
	 * Create an error DIDResolveResponse object.
	 *
	 * @param responseId the response id, normally same with the related request id
	 * @param code an error code
	 * @param message an error message, could be null
	 */
	protected DIDResolveResponse(String responseId, int code, String message) {
		super(responseId, code, message);
	}
}
