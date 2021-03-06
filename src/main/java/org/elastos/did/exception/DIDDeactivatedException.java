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
 * Unchecked exception thrown when an attempt is made to use a DID
 * that had been deactivated.
 */
public class DIDDeactivatedException extends IllegalStateException {
	private static final long serialVersionUID = -3106736642975911944L;

	/**
	 * Constructs the DIDDeactivatedException.
	 */
	public DIDDeactivatedException() {
		super();
	}

	/**
	 * Constructs the DIDDeactivatedException with the given message.
	 *
	 * @param message the message string
	 */
	public DIDDeactivatedException(String message) {
		super(message);
	}

	/**
	 * Constructs the DIDDeactivatedException with the given message and the reason.
	 *
	 * @param message the message string
	 * @param cause the reason
	 */
	public DIDDeactivatedException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Constructs the DIDDeactivatedException with the given reason.
	 *
	 * @param cause the reason
	 */
	public DIDDeactivatedException(Throwable cause) {
		super(cause);
	}
}
