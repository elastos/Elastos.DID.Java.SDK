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

public interface CredentialMetadata {
	/**
	 * Set alias for credential.
	 *
	 * @param alias
	 * alias string
	 */
	public void setAlias(String alias);

	/**
	 * Get alias from credential.
	 *
	 * @return alias string
	 */
	public String getAlias();

	/**
	 * Get last modified time for credential.
	 *
	 * @return last modified time
	 */
	public Date getLastModified();

	/**
	 * Set Extra element for credential.
	 *
	 * @param key the key string
	 * @param value the value string
	 */
	public void setExtra(String key, String value);

	/**
	 * Get Extra string according to the key string.
	 *
	 * @param key the key string
	 * @return the extra string matched key string
	 */
	public String getExtra(String key);
}
