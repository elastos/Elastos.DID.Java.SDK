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

package org.elastos.did;

import java.util.Date;

public interface DIDMetadata {
	/**
	 * Set alias for DID.
	 *
	 * @param alias the alias string
	 */
	public void setAlias(String alias);

	/**
	 * Get alias from DID.
	 *
	 * @return the alias string
	 */
	public String getAlias();

	/**
	 * Get the last transaction id.
	 *
	 * @return the transaction string
	 */
	public String getTransactionId();

	/**
	 * Get the document signature from the previous transaction.
	 *
	 * @return the signature string
	 */
	public String getPreviousSignature();

	/**
	 * Get the document signature from the lastest transaction.
	 *
	 * @return the signature string
	 */
	public String getSignature();

	/**
	 * Get the time of the lastest published transaction.
	 *
	 * @return the published time
	 */
	public Date getPublished();

	/**
	 * Get the last modified time for local did document.
	 *
	 * @return the last modified time
	 */
	public Date getLastModified();

	/**
	 * the DID deactivated status.
	 *
	 * @return the returned value is true if the did is deactivated.
	 *         the returned value is false if the did is activated.
	 */
	public boolean isDeactivated();

	/**
	 * Set extra element for user.
	 *
	 * @param key the key string
	 * @param value the value string
	 */
	public void setExtra(String key, String value);

	/**
	 * Get the value according to the key.
	 *
	 * @param key the key string
	 * @return the value string
	 */
	public String getExtra(String key);
}
