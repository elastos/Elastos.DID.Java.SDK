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

package org.elastos.did.exception;

/**
 * Thrown to indicate that the Resolve Result is malformed.
 */
public class MalformedResolveResultException extends DIDResolveException {
	private static final long serialVersionUID = -6564279904659655505L;

	/**
	 * Constructs the MalformedResolveResultException.
	 */
	public MalformedResolveResultException() {
        super();
    }

	/**
	 * Constructs the MalformedResolveResultException with the given message.
	 *
	 * @param message the message string
	 */
    public MalformedResolveResultException(String message) {
        super(message);
    }

    /**
     * Constructs the MalformedResolveResultException with the given message and the reason.
     *
     * @param message the message string
     * @param cause the reason
     */
    public MalformedResolveResultException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs the MalformedResolveResultException with the given reason.
     *
     * @param cause the reason
     */
    public MalformedResolveResultException(Throwable cause) {
        super(cause);
    }
}
