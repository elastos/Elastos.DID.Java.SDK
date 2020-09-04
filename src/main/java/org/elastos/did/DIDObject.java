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

public class DIDObject {
	private DIDURL id;
	private String type;

	/**
	 * Constructs the empty DIDObject.
	 */
	protected DIDObject() {
	}

	/**
	 * Constructs the DIDObject with the given value.
	 *
	 * @param id  the identifier of DIDObject
	 * @param type the DIDObject type
	 */
	protected DIDObject(DIDURL id, String type) {
		this.id = id;
		this.type = type;
	}

	/**
	 * Get the identifier of DIDObject.
	 *
	 * @return the identifier object
	 */
	public DIDURL getId() {
		return id;
	}

	/**
	 * Set the identifier of DIDObject.
	 *
	 * @param id the identifier object
	 */
	protected void setId(DIDURL id) {
		this.id = id;
	}

	/**
	 * Get the type of DIDObject.
	 *
	 * @return the type string
	 */
	public String getType() {
		return type;
	}

	/**
	 * Set the type of DIDObject.
	 *
	 * @param type the type string
	 */
	protected void setType(String type) {
		this.type = type;
	}
}
