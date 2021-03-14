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

import static com.google.common.base.Preconditions.checkArgument;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;

import org.elastos.did.DefaultDIDAdapter;
import org.elastos.did.exception.DIDTransactionException;

/**
 * The DIDAdapter implementation for the Simulated ID chain.
 */
public class SimulatedIDChainAdapter extends DefaultDIDAdapter {
	private URL idtxEndpoint;

	/**
	 * Create a SimulatedIDChainAdapter instance at the endpoint.
	 *
	 * @param endpoint the HTTP server endpoint of the simulated ID chain
	 * @throws MalformedURLException if the endpoint is malformed
	 */
	public SimulatedIDChainAdapter(URL endpoint) throws MalformedURLException {
		super(new URL(endpoint, "resolve"));
		idtxEndpoint = new URL(endpoint, "idtx");
	}

	/**
	 * Create and publish the ID transaction.
	 *
	 * @param payload the ID request as transaction payload
	 * @param memo the extra memo for this transaction
	 */
	@Override
	public void createIdTransaction(String payload, String memo)
			throws DIDTransactionException {
		checkArgument(payload != null && !payload.isEmpty(), "Invalid payload");

		try {
			InputStream is = performRequest(idtxEndpoint, payload);
			if (is != null)
				is.close();
		} catch (IOException e) {
			throw new DIDTransactionException("Create ID transaction failed.", e);
		}
	}
}
