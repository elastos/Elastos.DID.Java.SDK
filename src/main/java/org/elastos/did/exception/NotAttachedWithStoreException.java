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
 * Unchecked exception thrown when an attempt is made to an operation
 * that requires DID store but current object not attached with a store.
 */
public class NotAttachedWithStoreException extends IllegalStateException {
	private static final long serialVersionUID = 3066729105437341275L;

	/**
	 * Constructs a NotAttachedWithStoreException with null as its error
	 * detail message.
	 */
	public NotAttachedWithStoreException() {
		super();
	}

	/**
	 * Constructs a NotAttachedWithStoreException with the specified
	 * detail message.
	 *
	 * @param message The detail message
	 */
	public NotAttachedWithStoreException(String message) {
		super(message);
	}

	/**
	 * Constructs a NotAttachedWithStoreException with the specified detail
	 * message and cause.
	 *
	 * Note that the detail message associated with cause is not automatically
	 * incorporated into this exception's detail message.
	 *
	 * @param message The detail message
	 * @param cause The cause. A null value is permitted, and indicates
	 * 			that the cause is nonexistent or unknown
	 */
	public NotAttachedWithStoreException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Constructs a NotAttachedWithStoreException with the specified cause
	 * and a detail message from that cause.
	 *
	 * @param cause The cause. A null value is permitted, and indicates
	 * 			that the cause is nonexistent or unknown
	 */
	public NotAttachedWithStoreException(Throwable cause) {
		super(cause);
	}
}
