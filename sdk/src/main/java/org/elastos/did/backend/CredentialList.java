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
import java.util.Iterator;
import java.util.List;

import org.elastos.did.DID;
import org.elastos.did.DIDURL;
import org.elastos.did.exception.MalformedResolveResultException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * Credential list result object. When list credentials from the ID chain,
 * the resolver will return the credential ids that encapsulated in this object.
 */
@JsonPropertyOrder({ CredentialList.DID, CredentialList.CREDENTIALS })
public class CredentialList extends ResolveResult<CredentialList>
		implements Iterable<DIDURL> {
	protected static final String DID = "did";
	protected static final String CREDENTIALS = "credentials";

	/**
	 * Default page size.
	 */
	public static final int DEFAULT_SIZE = 128;
	/**
	 * Maximum page size.
	 */
	public static final int MAX_SIZE = 256;

	@JsonProperty(DID)
	private DID did;
	@JsonProperty(CREDENTIALS)
	@JsonInclude(Include.NON_EMPTY)
	private List<DIDURL> credentialIds;

	/**
	 * Construct a CredentialList for specific DID.
	 *
	 * @param did the target DID
	 */
	@JsonCreator
	protected CredentialList(@JsonProperty(value = DID, required = true)DID did) {
		this.did = did;
	}

	/**
	 * Get the target DID that this list belongs to.
	 *
	 * @return the target DID
	 */
	public DID getDid() {
		return did;
	}

	/**
	 * Returns the number of credential ids in this list.
	 *
	 * @return the number of credential ids
	 */
	public int size() {
		return credentialIds != null ? credentialIds.size() : 0;
	}

	/**
	 * Returns the credential id at the specified position in this list.
	 *
	 * @param index the index of the credential id to return
	 * @return the credential id at the specified position in this list
	 */
	public DIDURL getCredentialId(int index) {
		return credentialIds != null ? credentialIds.get(index) : null;
	}

	/**
	 * Returns all credential ids in this list.
	 *
	 * @return the read-only list object of all credential ids
	 */
	public List<DIDURL> getCredentialIds() {
		return Collections.unmodifiableList(credentialIds != null ?
				credentialIds : Collections.emptyList());
	}

	/**
	 * Appends the specified credential id to the end of this list object.
	 *
	 * @param id the credential id to be add
	 */
	protected synchronized void addCredentialId(DIDURL id) {
		if (credentialIds == null)
			this.credentialIds = new ArrayList<DIDURL>(DEFAULT_SIZE);

		credentialIds.add(id);
	}

	/**
	 * Post sanitize routine after deserialization.
	 *
	 * @throws MalformedResolveResultException if the CredentialList
	 * 		   object is invalid
	 */
	@Override
	protected void sanitize() throws MalformedResolveResultException {
		if (did == null)
			throw new MalformedResolveResultException("Missing did");
	}

	/**
	 * Returns an iterator over the credential ids in this list in proper
	 * sequence. The returned iterator is read-only because of the backing
	 * CredentialList object is a read-only object.
	 *
	 * @return an read-only iterator over the credential ids in this list
	 * 		   in proper sequence
	 */
	@Override
	public Iterator<DIDURL> iterator() {
		return credentialIds != null ? Collections.unmodifiableList(credentialIds).iterator() :
				Collections.emptyIterator();
	}
}
