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

import static com.google.common.base.Preconditions.checkArgument;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDTransactionException;
import org.elastos.did.exception.NetworkException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultDIDAdapter implements DIDAdapter {
	private static final String MAINNET_RESOLVER = "http://api.elastos.io:20606";
	private static final String TESTNET_RESOLVER = "http://api.elastos.io:21606";

	private URL resolver;

	private static final Logger log = LoggerFactory.getLogger(DefaultDIDAdapter.class);

	/**
	 * Set default resolver according to specified url.
	 *
	 * @param resolver the resolver url string
	 * @throws IllegalArgumentException throw this exception if setting resolver url failed.
	 */
	public DefaultDIDAdapter(String resolver) {
		checkArgument(resolver != null && !resolver.isEmpty(), "Invalid resolver URL");

		switch (resolver.toLowerCase()) {
		case "mainnet":
			resolver = MAINNET_RESOLVER;
			break;

		case "testnet":
			resolver = TESTNET_RESOLVER;
			break;
		}

		try {
			this.resolver = new URL(resolver);
		} catch (MalformedURLException e) {
			throw new IllegalArgumentException("Invalid resolver URL", e);
		}
	}

	protected InputStream performRequest(URL url, String body) throws IOException {
		HttpURLConnection connection = (HttpURLConnection)url.openConnection();
		connection.setRequestMethod("POST");
		connection.setRequestProperty("User-Agent",
				"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.95 Safari/537.11");
		connection.setRequestProperty("Content-Type", "application/json");
		connection.setRequestProperty("Accept", "application/json");
		connection.setDoOutput(true);
		connection.connect();

		OutputStream os = connection.getOutputStream();
		os.write(body.getBytes());
		os.close();

		int code = connection.getResponseCode();
		if (code < 200 || code > 299) {
			log.error("HTTP request error, status: {}, message: {}",
					code, connection.getResponseMessage());
			throw new IOException("HTTP error with status: " + code);
		}

		return connection.getInputStream();
	}

	@Override
	public InputStream resolve(String request) throws DIDResolveException {
		try {
			return performRequest(resolver, request);
		} catch (IOException e) {
			throw new NetworkException("Network error.", e);
		}
	}

	@Override
	public void createIdTransaction(String payload, String memo)
			throws DIDTransactionException {
		throw new UnsupportedOperationException("Not implemented");

	}
}
