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

package org.elastos.did.backend;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.elastos.did.DID;
import org.elastos.did.DIDURL;
import org.elastos.did.exception.MalformedResolveResultException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({ CredentialList.DID, CredentialList.CREDENTIALS })
public class CredentialList extends ResolveResult<CredentialList> {
	protected static final String DID = "did";
	protected static final String CREDENTIALS = "credentials";

	public static final int DEFAULT_SIZE = 128;
	public static final int MAX_SIZE = 512;

	@JsonProperty(DID)
	private DID did;
	@JsonProperty(CREDENTIALS)
	private List<DIDURL> credentialIds;

	@JsonCreator
	private CredentialList() {
	}

	protected CredentialList(DID did) {
		this.did = did;
		this.credentialIds = new ArrayList<DIDURL>(DEFAULT_SIZE);
	}

	public DID getDid() {
		return did;
	}

	public List<DIDURL> getCredentialIds() {
		if (credentialIds == null || credentialIds.size() == 0)
			return null;

		return Collections.unmodifiableList(credentialIds);
	}

	public int size() {
		return credentialIds.size();
	}

	public DIDURL getCredentialId(int index) {
		return credentialIds.get(index);
	}

	protected void addCredentialId(DIDURL id) {
		credentialIds.add(id);
	}

	@Override
	protected void sanitize() throws MalformedResolveResultException {
		if (did == null)
			throw new MalformedResolveResultException("Missing did");
	}
}
