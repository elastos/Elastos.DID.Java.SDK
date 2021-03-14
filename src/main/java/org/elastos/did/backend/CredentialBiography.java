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

import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.elastos.did.DIDURL;
import org.elastos.did.exception.MalformedIDChainTransactionException;
import org.elastos.did.exception.MalformedResolveResultException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Biography of a verifiable credential, include the credential
 * status and all credential transactions.
 */
@JsonPropertyOrder({ CredentialBiography.ID,
	CredentialBiography.STATUS,
	CredentialBiography.TRANSACTION })
public class CredentialBiography extends ResolveResult<CredentialBiography>
		implements Iterable<CredentialTransaction> {
	protected final static String ID = "id";
	protected final static String STATUS = "status";
	protected final static String TRANSACTION = "transaction";

	/**
	 * Defines the status of a credential.
	 */
	public static enum Status {
		/**
		 * The credential is valid.
		 */
		VALID(0),
		/*
		 * The credential is expired.
		 */
		// EXPIRED,
		/**
		 * The credential is revoked.
		 */
		REVOKED(2),
		/**
		 * The credential is not published.
		 */
		NOT_FOUND(3);

		private int value;

		private Status(int value) {
			this.value = value;
		}

		/**
		 * Returns the value of this enumeration constant.
		 *
		 * @return the int value
		 */
		@JsonValue
		public int getValue() {
			return value;
		}

		/**
		 * Returns the Status enumeration constant of the specified value.
		 *
		 * @param value the int value
		 * @return the enumeration constant
		 */
		@JsonCreator
		public static Status valueOf(int value) {
			switch (value) {
			case 0:
				return VALID;

			case 2:
				return REVOKED;

			case 3:
				return NOT_FOUND;

			default:
				throw new IllegalArgumentException("Invalid status value: " + value);
			}
		}

		/**
		 * Returns the name of this enumeration constant in low case,
		 * as contained in the declaration.
		 */
		@Override
		public String toString() {
			return name().toLowerCase();
		}
	}

	@JsonProperty(ID)
	private DIDURL id;
	@JsonProperty(STATUS)
	private Status status;
	@JsonProperty(TRANSACTION)
	private List<CredentialTransaction> txs;

	/**
	 * Constructs the CredentialBiography instance with the given value.
	 *
	 * @param id the target credential id
	 * @param status the credential status
	 */
	@JsonCreator
	protected CredentialBiography(@JsonProperty(value = ID, required = true)DIDURL id,
			@JsonProperty(value = STATUS, required = true) Status status) {
		this.id = id;
		this.status = status;
	}

	/**
	 * Constructs the CredentialBiography instance with the given value.
	 * The default credential status is VALID.
	 *
	 * @param id the target credential id
	 */
	protected CredentialBiography(DIDURL id) {
		this(id, Status.VALID);
	}

	/**
	 * Get the credential id.
	 *
	 * @return the credential id
	 */
	public DIDURL getId() {
		return id;
	}

	/**
	 * Set the status of the credential.
	 *
	 * @param status the credential status
	 */
	protected void setStatus(Status status) {
		this.status = status;
	}

	/**
	 * Get the status of the credential.
	 *
	 * @return the credential status
	 */
	public Status getStatus() {
		return status;
	}

	/**
	 * Returns the number of transactions in this biography.
	 *
	 * @return the number of transactions
	 */
	public int size() {
		return txs != null ? txs.size() : 0;
	}

	/**
	 * Returns the transaction at the specified position in this biography.
	 *
	 * @param index the index of the transaction to return
	 * @return the transaction at the specified position in this biography
	 */
	public CredentialTransaction getTransaction(int index) {
		return txs != null ? txs.get(index) : null;
	}

	/**
	 * Returns all transactions in this biography.
	 *
	 * @return the read-only list object of all transactions
	 */
	public List<CredentialTransaction> getAllTransactions() {
		return Collections.unmodifiableList(txs != null ? txs : Collections.emptyList());
	}

	/**
	 * Appends the specified credential transaction to the end of this
	 * biography object.
	 *
	 * @param tx the CredentialTransaction object to be add
	 */
	protected synchronized void addTransaction(CredentialTransaction tx) {
		if (txs == null)
			txs = new LinkedList<CredentialTransaction>();

		txs.add(tx);
	}

	/**
	 * Post sanitize routine after deserialization.
	 *
	 * @throws MalformedResolveResultException if the CredentialBiography
	 * 		   object is invalid
	 */
	@Override
	protected void sanitize() throws MalformedResolveResultException {
		if (id == null)
			throw new MalformedResolveResultException("Missing id");

		if (status != Status.NOT_FOUND) {
			if (txs == null || txs.size() == 0)
				throw new MalformedResolveResultException("Missing transaction");

			try {
				for (CredentialTransaction tx : txs)
					tx.sanitize();
			} catch (MalformedIDChainTransactionException e) {
				throw new MalformedResolveResultException("Invalid transaction", e);
			}
		} else {
			if (txs != null)
				throw new MalformedResolveResultException("Should not include transaction");
		}
	}

	/**
	 * Returns an iterator over the transactions in this biography in proper
	 * sequence. The returned iterator is read-only because of the backing
	 * CredentialBiography object is a read-only object.
	 *
	 * @return an read-only iterator over the transactions in this biography
	 * 		   in proper sequence
	 */
	@Override
	public Iterator<CredentialTransaction> iterator() {
		return txs != null ? Collections.unmodifiableList(txs).iterator() :
				Collections.emptyIterator();
	}
}
