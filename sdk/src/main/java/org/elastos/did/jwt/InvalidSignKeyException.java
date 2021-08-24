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

package org.elastos.did.jwt;

/**
 * Unchecked exception thrown indicate that the signing key used to sign
 * the JWT is invalid.
 */
public class InvalidSignKeyException extends RuntimeException {
	private static final long serialVersionUID = 248013710632693139L;

	/**
	 * Constructs an InvalidSignKeyException with null as its error
	 * detail message.
	 */
	public InvalidSignKeyException() {
		super();
	}

	/**
	 * Constructs an InvalidSignKeyException with the specified detail message.
	 *
	 * @param message The detail message
	 */
	public InvalidSignKeyException(String message) {
		super(message);
	}

	/**
	 * Constructs an InvalidSignKeyException with the specified detail message
	 * and cause.
	 *
	 * Note that the detail message associated with cause is not automatically
	 * incorporated into this exception's detail message.
	 *
	 * @param message The detail message
	 * @param cause The cause. A null value is permitted, and indicates
	 * 			that the cause is nonexistent or unknown
	 */
	public InvalidSignKeyException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Constructs an InvalidSignKeyException with the specified cause and
	 * a detail message from that cause.
	 *
	 * @param cause The cause. A null value is permitted, and indicates
	 * 			that the cause is nonexistent or unknown
	 */
	public InvalidSignKeyException(Throwable cause) {
		super(cause);
	}
}
