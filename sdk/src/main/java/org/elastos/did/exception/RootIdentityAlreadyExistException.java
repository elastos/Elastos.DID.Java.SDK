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
 * Unchecked exception thrown when an attempt is made to create a
 * RootIdentity that already exists.
 */
public class RootIdentityAlreadyExistException extends IllegalStateException {
	private static final long serialVersionUID = -7962741794379789111L;

	/**
	 * Constructs a RootIdentityAlreadyExistException with null as its error
	 * detail message.
	 */
	public RootIdentityAlreadyExistException() {
		super();
	}

	/**
	 * Constructs a RootIdentityAlreadyExistException with the specified
	 * detail message.
	 *
	 * @param message The detail message
	 */
	public RootIdentityAlreadyExistException(String message) {
		super(message);
	}

	/**
	 * Constructs a RootIdentityAlreadyExistException with the specified detail
	 * message and cause.
	 *
	 * Note that the detail message associated with cause is not automatically
	 * incorporated into this exception's detail message.
	 *
	 * @param message The detail message
	 * @param cause The cause. A null value is permitted, and indicates
	 * 			that the cause is nonexistent or unknown
	 */
	public RootIdentityAlreadyExistException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Constructs a RootIdentityAlreadyExistException with the specified cause
	 * and a detail message from that cause.
	 *
	 * @param cause The cause. A null value is permitted, and indicates
	 * 			that the cause is nonexistent or unknown
	 */
	public RootIdentityAlreadyExistException(Throwable cause) {
		super(cause);
	}
}
