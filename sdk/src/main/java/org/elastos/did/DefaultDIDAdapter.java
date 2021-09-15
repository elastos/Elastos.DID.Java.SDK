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
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDTransactionException;
import org.elastos.did.exception.NetworkException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * The default DIDAdapter implementation for the Elastos ID chain.
 *
 * <p>
 * This adapter only provided resolve capability, it means you can not publish
 * ID transactions with this adapter. The sub class can implement the
 * createIdTransaction method to support publish capability.
 * </p>
 */
public class DefaultDIDAdapter implements DIDAdapter {
	private static final String[] MAINNET_RESOLVERS = {
			"https://api.elastos.io/eid",
			"https://api.trinity-tech.cn/eid"
	};

	private static final String[] TESTNET_RESOLVERS = {
			"https://api-testnet.elastos.io/eid",
			"https://api-testnet.trinity-tech.cn/eid",
	};

	private URL resolver;

	private static final Logger log = LoggerFactory.getLogger(DefaultDIDAdapter.class);

	static class CheckResult implements Comparable<CheckResult> {
		private static final BigInteger MAX_DIFF = BigInteger.valueOf(10);

		public URL endpoint;
		public int latency;
		public BigInteger lastBlock;

		public CheckResult(URL endpoint, int latency, BigInteger lastBlock) {
			this.endpoint = endpoint;
			this.latency = latency;
			this.lastBlock = lastBlock;
		}

		public CheckResult(URL endpoint) {
			this(endpoint, -1, null);
		}

		@Override
		public int compareTo(CheckResult o) {
			if (o == null)
				return -1;

			if (o.latency < 0 && this.latency < 0)
				return 0;

			if (o.latency < 0 || this.latency < 0)
				return this.latency < 0 ? 1 : -1;

			BigInteger diff = o.lastBlock.subtract(this.lastBlock);
			if (diff.abs().compareTo(MAX_DIFF) > 0)
				return diff.signum();

			if (this.latency == o.latency) {
				return diff.signum();
			} else {
				return this.latency - o.latency;
			}
		}

		public boolean available() {
			return this.latency >= 0;
		}
	}

	/**
	 * Create a DefaultDIDAdapter instance with given resolver endpoint.
	 *
	 * @param resolver the resolver url string
	 */
	public DefaultDIDAdapter(String resolver) {
		checkArgument(resolver != null && !resolver.isEmpty(), "Invalid resolver URL");
		String[] endpoints = null;

		switch (resolver.toLowerCase()) {
		case "mainnet":
			resolver = MAINNET_RESOLVERS[0];
			endpoints = MAINNET_RESOLVERS;
			break;

		case "testnet":
			resolver = TESTNET_RESOLVERS[0];
			endpoints = TESTNET_RESOLVERS;
			break;

		default:
			break;
		}

		try {
			this.resolver = new URL(resolver);
		} catch (MalformedURLException e) {
			throw new IllegalArgumentException("Invalid resolver URL", e);
		}

		if (endpoints != null)
			checkNetwork(endpoints);
	}

	private CheckResult checkEndpoint(URL endpoint) {
		log.info("Checking the resolver {}...", endpoint);

		ObjectMapper mapper = new ObjectMapper();
		ObjectNode json = mapper.createObjectNode();
		long id = System.currentTimeMillis();
		json.put("id", id);
		json.put("jsonrpc", "2.0");
		json.put("method", "eth_blockNumber");
		try {
			String body = mapper.writeValueAsString(json);
			long start = System.currentTimeMillis();
			InputStream is = httpPost(endpoint, body);
			int latency = (int)(System.currentTimeMillis() - start);
			JsonNode result = mapper.readTree(is);
			if (result.get("id").asLong() != id)
				throw new IOException("Invalid JSON RPC id.");

			String n = result.get("result").asText();
			if (n.startsWith("0x"))
				n = n.substring(2);
			BigInteger blockNumber = new BigInteger(n, 16);

			log.info("Checking the resolver {}...latency: {}, lastBlock: {}",
					endpoint, latency, n);
			return new CheckResult(endpoint, latency, blockNumber);
		} catch (Exception e) {
			log.info("Checking the resolver {}...error", endpoint);
			return new CheckResult(endpoint);
		}
	}

	private void checkNetwork(String[] endpoints) {
		List<CompletableFuture<CheckResult>> futures = new ArrayList<CompletableFuture<CheckResult>>(endpoints.length);

		for (String endpoint : endpoints) {
			try {
				URL url = new URL(endpoint);
				futures.add(CompletableFuture.supplyAsync(() -> {
					return checkEndpoint(url);
				}));
			} catch (MalformedURLException ignore) {
			}
		}

		CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
		List<CheckResult> results = new ArrayList<CheckResult>(futures.size());
		for (CompletableFuture<CheckResult> future : futures) {
			try {
				results.add(future.get());
			} catch (Exception ignore) {
			}
		}

		if (results.size() > 0) {
			results.sort(null);

			CheckResult best = results.get(0);
			if (best.available()) {
				this.resolver = best.endpoint;
				log.info("Update resolver to {}", resolver.toString());
			}
		}
	}

	/**
	 * Create a DefaultDIDAdapter instance with given resolver endpoint.
	 *
	 * @param resolver the resolver URL object
	 */
	public DefaultDIDAdapter(URL resolver) {
		checkArgument(resolver != null, "Invalid resolver URL");
		this.resolver = resolver;
	}

	/**
	 * Perform a HTTP POST request with given request body to the url.
	 *
	 * @param url the target HTTP endpoint
	 * @param body the request body
	 * @return an input stream object of the response body
	 * @throws IOException if an error occurred when processing the request
	 */
	protected InputStream httpPost(URL url, String body) throws IOException {
		return httpPost(url, null, body);
	}

	/**
	 * Perform a HTTP POST request with given request body to the url.
	 *
	 * @param url the target HTTP endpoint
	 * @param headers the customized request headers
	 * @param body the request body
	 * @return an input stream object of the response body
	 * @throws IOException if an error occurred when processing the request
	 */
	protected InputStream httpPost(URL url, Map<String, String> headers, String body)
			throws IOException {
		HttpURLConnection connection = (HttpURLConnection)url.openConnection();
		connection.setRequestMethod("POST");

		if (headers == null || !headers.containsKey("User-Agent"))
			connection.setRequestProperty("User-Agent",
					"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.95 Safari/537.11");

		if (headers == null || !headers.containsKey("Content-Type"))
			connection.setRequestProperty("Content-Type", "application/json");

		if (headers == null || !headers.containsKey("Accept"))
			connection.setRequestProperty("Accept", "*/*");

		if (headers != null) {
			for (Map.Entry<String, String> header : headers.entrySet())
				connection.addRequestProperty(header.getKey(), header.getValue());
		}

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

	/**
	 * Perform a HTTP GET request to the url.
	 *
	 * @param url the target HTTP endpoint
	 * @return an input stream object of the response body
	 * @throws IOException if an error occurred when processing the request
	 */
	protected InputStream httpGet(URL url) throws IOException {
		return httpGet(url, null);
	}

	/**
	 * Perform a HTTP GET request to the url.
	 *
	 * @param url the target HTTP endpoint
	 * @param headers the customized request headers
	 * @return an input stream object of the response body
	 * @throws IOException if an error occurred when processing the request
	 */
	protected InputStream httpGet(URL url, Map<String, String> headers)
			throws IOException {
		HttpURLConnection connection = (HttpURLConnection)url.openConnection();
		connection.setRequestMethod("GET");

		if (headers == null || !headers.containsKey("User-Agent"))
			connection.setRequestProperty("User-Agent",
					"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.95 Safari/537.11");

		if (headers == null || !headers.containsKey("Content-Type"))
			connection.setRequestProperty("Content-Type", "application/json");

		if (headers == null || !headers.containsKey("Accept"))
			connection.setRequestProperty("Accept", "*/*");

		if (headers != null) {
			for (Map.Entry<String, String> header : headers.entrySet())
				connection.addRequestProperty(header.getKey(), header.getValue());
		}

		connection.connect();

		int code = connection.getResponseCode();
		if (code < 200 || code > 299) {
			log.error("HTTP request error, status: {}, message: {}",
					code, connection.getResponseMessage());
			throw new IOException("HTTP error with status: " + code);
		}

		return connection.getInputStream();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public InputStream resolve(String request) throws DIDResolveException {
		checkArgument(request != null && !request.isEmpty(), "Invalid request");

		try {
			log.debug("Resolving via {}", resolver.toString());
			return httpPost(resolver, request);
		} catch (IOException e) {
			throw new NetworkException("Network error.", e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void createIdTransaction(String payload, String memo)
			throws DIDTransactionException {
		throw new UnsupportedOperationException("Not implemented");
	}
}
