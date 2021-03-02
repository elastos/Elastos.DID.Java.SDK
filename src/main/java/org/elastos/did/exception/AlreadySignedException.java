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
 * Object already signed by the specific DID.
 */
public class AlreadySignedException extends IllegalStateException {
	private static final long serialVersionUID = -7009590984618280753L;

	/**
	 * Constructs the AlreadySignedException.
	 */
	public AlreadySignedException() {
        super();
    }

	/**
	 * Constructs the AlreadySignedException with the given message.
	 *
	 * @param message the message string
	 */
    public AlreadySignedException(String message) {
        super(message);
    }

    /**
     * Constructs the AlreadySignedException with the given message and the reason.
     *
     * @param message the message string
     * @param cause the reason
     */
    public AlreadySignedException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs the AlreadySignedException with the given reason.
     *
     * @param cause the reason
     */
    public AlreadySignedException(Throwable cause) {
        super(cause);
    }
}
