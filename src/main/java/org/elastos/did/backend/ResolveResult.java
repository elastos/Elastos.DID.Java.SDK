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

import java.io.IOException;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.elastos.did.DID;
import org.elastos.did.DIDHistory;
import org.elastos.did.DIDTransaction;
import org.elastos.did.exception.DIDTransactionException;
import org.elastos.did.exception.MalformedResolveResultException;
import org.elastos.did.util.JsonHelper;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ResolveResult implements DIDHistory {
	private final static String DID = "did";
	private final static String STATUS = "status";
	private final static String TRANSACTION = "transaction";

	private DID did;
	private int status;
	private List<IDChainTransaction> idtxs;

	/**
	 * Constructs the Resolve Result with the given value.
	 *
	 * @param did the specified DID
	 * @param status the DID's status
	 */
	protected ResolveResult(DID did, int status) {
		this.did = did;
		this.status = status;
	}

	@Override
	public DID getDid() {
		return did;
	}

	@Override
	public int getStatus() {
		return status;
	}

	@Override
	public int getTransactionCount() {
		if (idtxs == null)
			return 0;

		return idtxs.size();
	}

	/**
	 * Get the index transaction content.
	 *
	 * @param index the index
	 * @return the index IDChainTransaction content
	 * @throws DIDTransactionException Invalid ID transaction, can not verify the signature.
	 */
	public IDChainTransaction getTransactionInfo(int index)
			throws DIDTransactionException {
		if (idtxs == null)
			return null;

		IDChainTransaction tx = idtxs.get(index);
		if (!tx.getRequest().isValid())
			throw new DIDTransactionException("Invalid ID transaction, can not verify the signature.");

		return tx;
	}

	@Override
	public List<DIDTransaction> getAllTransactions() {
		List<DIDTransaction> txs = new ArrayList<DIDTransaction>(idtxs.size());
		txs.addAll(idtxs);
		return txs;
	}

	/**
	 * Add transaction infomation into IDChain Transaction.
	 * @param ti the IDChainTransaction object
	 */
	protected synchronized void addTransactionInfo(IDChainTransaction ti) {
		if (idtxs == null)
			idtxs = new LinkedList<IDChainTransaction>();

		idtxs.add(ti);
	}

    /**
     * Get json string from Resolve Result content.
     *
     * @param out the Writer handle
     * @throws IOException write field to json string failed.
     */
	public void toJson(Writer out) throws IOException {
		JsonFactory factory = new JsonFactory();
		JsonGenerator generator = factory.createGenerator(out);

		generator.writeStartObject();

		generator.writeStringField(DID, did.toString());
		generator.writeNumberField(STATUS, status);

		if (status != STATUS_NOT_FOUND) {
			generator.writeFieldName(TRANSACTION);
			generator.writeStartArray();

			for (IDChainTransaction ti : idtxs)
				ti.toJson(generator);

			generator.writeEndArray();
		}

		generator.writeEndObject();
		generator.close();
	}

	/**
	 * Get json string from Resolve Result content.
	 */
	public String toJson() throws IOException {
		Writer out = new StringWriter(4096);
		toJson(out);
		return out.toString();
	}

	/**
	 * Get Resolve Result object from input content.
	 *
	 * @param result the JsonNode input
	 * @return the ResolveResult object
	 * @throws MalformedResolveResultException the Resolve Result is malformed.
	 */
	public static ResolveResult fromJson(JsonNode result)
			throws MalformedResolveResultException {
		Class<MalformedResolveResultException> exceptionClass = MalformedResolveResultException.class;

		if (result == null || result.size() == 0)
			throw new MalformedResolveResultException("Empty resolve result.");

		DID did = JsonHelper.getDid(result, DID, false, null,
				"Resolved result DID", exceptionClass);

		int status = JsonHelper.getInteger(result, STATUS, false, -1,
					"Resolved status", exceptionClass);

		ResolveResult rr = new ResolveResult(did, status);

		if (status != STATUS_NOT_FOUND) {
			JsonNode txs = result.get(TRANSACTION);
			if (txs == null || !txs.isArray() || txs.size() == 0)
				throw new MalformedResolveResultException("Invalid resolve result, missing transaction.");

			for (int i = 0; i < txs.size(); i++) {
				try {
					IDChainTransaction ti = IDChainTransaction.fromJson(txs.get(i));
					rr.addTransactionInfo(ti);
				} catch (DIDTransactionException e) {
					new MalformedResolveResultException(e);
				}
			}
		}

		return rr;
	}

	/**
	 * Get Resolve Result object from input content.
	 *
	 * @param json the json input
	 * @return the ResolveResult object
	 * @throws MalformedResolveResultException the Resolve Result is malformed.
	 */
	public static ResolveResult fromJson(String json)
			throws MalformedResolveResultException {
		if (json == null || json.isEmpty())
			throw new IllegalArgumentException();

		ObjectMapper mapper = new ObjectMapper();
		try {
			JsonNode result = mapper.readTree(json);
			return fromJson(result);
		} catch (IOException e) {
			throw new MalformedResolveResultException("Parse resolve result error.", e);
		}
	}

	/**
	 * Get Resolve Result object from input content.
	 *
	 * @param in the Reader input
	 * @return the ResolveResult object
	 * @throws MalformedResolveResultException the Resolve Result is malformed.
	 */
	public static ResolveResult fromJson(Reader in)
			throws MalformedResolveResultException {
		if (in == null)
			throw new IllegalArgumentException();

		ObjectMapper mapper = new ObjectMapper();
		try {
			JsonNode result = mapper.readTree(in);
			return fromJson(result);
		} catch (IOException e) {
			throw new MalformedResolveResultException("Parse resolve result error.", e);
		}
	}

	@Override
	public String toString() {
		try {
			return toJson();
		} catch (IOException ignore) {
		}

		return super.toString();
	}
}
