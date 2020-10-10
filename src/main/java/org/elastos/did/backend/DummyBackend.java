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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Calendar;
import java.util.LinkedList;
import java.util.Random;

import org.elastos.did.Constants;
import org.elastos.did.DID;
import org.elastos.did.DIDAdapter;
import org.elastos.did.DIDResolver;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.DIDTransactionException;
import org.elastos.did.exception.MalformedDIDException;

public class DummyBackend implements DIDAdapter, DIDResolver {
	private static Random random = new Random();

	private boolean verbose;
	private LinkedList<IDChainTransaction> idtxs;

	public DummyBackend(boolean verbose) {
		this.verbose = verbose;

		idtxs = new LinkedList<IDChainTransaction>();
	}

	public DummyBackend() {
		this(false);
	}

	private static String generateTxid() {
        StringBuffer sb = new StringBuffer();
        while(sb.length() < 32){
            sb.append(Integer.toHexString(random.nextInt()));
        }

        return sb.toString();
    }

	private IDChainTransaction getLastTransaction(DID did) {
		for (IDChainTransaction tx : idtxs) {
			if (tx.getDid().equals(did))
				return tx;
		}

		return null;
	}

	@Override
	public void createIdTransaction(String payload, String memo)
			throws DIDTransactionException {
		IDChainRequest request;
		try {
			request = IDChainRequest.parse(payload, IDChainRequest.class);
		} catch (DIDSyntaxException e) {
			throw new DIDTransactionException(e);
		}

		if (verbose) {
			System.out.println("ID Transaction: " + request.getOperation()
					+ "[" + request.getDid() + "]");
			System.out.println("    " + request.toString(true));

			if (request.getOperation() != IDChainRequest.Operation.DEACTIVATE)
				System.out.println("    " + request.getDocument().toString(true));
		}

		if (!request.isValid())
			throw new DIDTransactionException("Invalid ID transaction request.");

		if (request.getOperation() != IDChainRequest.Operation.DEACTIVATE) {
			if (!request.getDocument().isValid())
				throw new DIDTransactionException("Invalid DID Document.");
		}

		IDChainTransaction tx = getLastTransaction(request.getDid());

		switch (request.getOperation()) {
		case CREATE:
			if (tx != null)
				throw new DIDTransactionException("DID already exist.");

			break;

		case UPDATE:
			if (tx == null)
				throw new DIDTransactionException("DID not exist.");

			if (tx.getOperation().equals(IDChainRequest.Operation.DEACTIVATE.toString()))
				throw new DIDTransactionException("DID already dactivated.");

			if (!request.getPreviousTxid().equals(tx.getTransactionId()))
				throw new DIDTransactionException("Previous transaction id missmatch.");

			break;

		case DEACTIVATE:
			if (tx == null)
				throw new DIDTransactionException("DID not exist.");

			if (tx.getOperation().equals(IDChainRequest.Operation.DEACTIVATE.toString()))
				throw new DIDTransactionException("DID already dactivated.");

			break;
		}

		tx = new IDChainTransaction(generateTxid(),
				Calendar.getInstance(Constants.UTC).getTime(), request);
		idtxs.add(0, tx);
	}

	@Override
	public InputStream resolve(String requestId, String did, boolean all)
			throws DIDResolveException {
		boolean matched = false;

		if (verbose)
			System.out.print("Resolve: " + did + "...");

		if (!did.startsWith("did:elastos:"))
			did = "did:elastos:" + did;

		DID target;
		try {
			target = new DID(did);
		} catch (MalformedDIDException e) {
			throw new DIDResolveException("Invalid did", e);
		}

		int status = 3;

		IDChainTransaction last = getLastTransaction(target);
		if (last != null) {
			if (last.getOperation().equals(IDChainRequest.Operation.DEACTIVATE.toString())) {
				status = 2;
		    } else {
				if (last.getRequest().getDocument().isExpired())
					status = 1;
				else
					status = 0;
			}

			matched = true;
		}

		ResolveResult rr = new ResolveResult(target, status);
		if (status != 3) {
			for (IDChainTransaction tx : idtxs) {
				if (tx.getDid().equals(target)) {
					rr.addTransaction(tx);;

					if (!all)
						break;
				}
			}
		}

		ResolveResponse response = new ResolveResponse(requestId, rr);
		InputStream os = new ByteArrayInputStream(response.toString(true).getBytes());

		if (verbose)
			System.out.println(matched ? "success" : "failed");

		return os;
	}

	public void reset() {
		idtxs.clear();
	}
}
