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

public class CredentialExpiredException extends CredentialInvalidException {
	private static final long serialVersionUID = -5358238572068160552L;

	/**
	 * Constructs the CredentialExpiredException.
	 */
	public CredentialExpiredException() {
        super();
    }

	/**
	 * Constructs the CredentialExpiredException with the given message.
	 *
	 * @param message the message string
	 */
    public CredentialExpiredException(String message) {
        super(message);
    }

    /**
     * Constructs the CredentialExpiredException with the given message and the reason.
     *
     * @param message the message string
     * @param cause the reason
     */
    public CredentialExpiredException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs the CredentialExpiredException with the given reason.
     *
     * @param cause the reason
     */
    public CredentialExpiredException(Throwable cause) {
        super(cause);
    }
}
