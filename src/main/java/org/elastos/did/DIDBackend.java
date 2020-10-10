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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Random;

import org.elastos.did.backend.IDChainRequest;
import org.elastos.did.backend.IDChainTransaction;
import org.elastos.did.backend.ResolveRequest;
import org.elastos.did.backend.ResolveResponse;
import org.elastos.did.backend.ResolveResult;
import org.elastos.did.backend.ResolverCache;
import org.elastos.did.exception.DIDDeactivatedException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.DIDTransactionException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.NetworkException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The class is to provide the backend for resolving DID.
 */
public class DIDBackend {
	private static final long DEFAULT_TTL = 24 * 60 * 60 * 1000;
	private static DIDResolver resolver;
	private static ResolveHandle resolveHandle;

	private static Random random = new Random();
	private static long ttl = DEFAULT_TTL; // milliseconds

	private DIDAdapter adapter;

	private static final Logger log = LoggerFactory.getLogger(DIDBackend.class);

	/**
	 * The interface to indicate how to get local did document, if this did is not published to chain.
	 */
	public interface ResolveHandle {
		/**
		 * Resolve DID content(DIDDocument).
		 *
		 * @param did the DID object
		 * @return DIDDocument object
		 */
		public DIDDocument resolve(DID did);
	}

	static class DefaultResolver implements DIDResolver {
		private URL url;

		private static final Logger log = LoggerFactory.getLogger(DefaultResolver.class);

		/**
		 * Set default resolver according to specified url.
		 *
		 * @param resolver the resolver url string
		 * @throws DIDResolveException throw this exception if setting resolver url failed.
		 */
		public DefaultResolver(String resolver) throws DIDResolveException {
			if (resolver == null || resolver.isEmpty())
				throw new IllegalArgumentException();

			try {
				this.url = new URL(resolver);
			} catch (MalformedURLException e) {
				throw new DIDResolveException(e);
			}
		}

		@Override
		public InputStream resolve(String requestId, String did, boolean all)
				throws DIDResolveException {
			try {
				log.debug("Resolving {}...", did.toString());

				HttpURLConnection connection = (HttpURLConnection)url.openConnection();
				connection.setRequestMethod("POST");
				connection.setRequestProperty("User-Agent",
						"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.95 Safari/537.11");
				connection.setRequestProperty("Content-Type", "application/json");
				connection.setRequestProperty("Accept", "application/json");
				connection.setDoOutput(true);
				connection.connect();

				OutputStream os = connection.getOutputStream();
				ResolveRequest request = new ResolveRequest(requestId, ResolveRequest.METHOD_RESOLVE_DID);
				request.setParameter(did, all);
				try {
					request.serialize(os, true);
				} catch (DIDSyntaxException ignore) {
					log.error("INTERNAL - Serialize resolve request", ignore);
				} finally {
					os.close();
				}

				int code = connection.getResponseCode();
				if (code != 200) {
					log.error("Resolve {} error, status: {}, message: {}",
							did.toString(), code, connection.getResponseMessage());
					throw new DIDResolveException("HTTP error with status: " + code);
				}

				return connection.getInputStream();
			} catch (IOException e) {
				log.error("Resovle " + did + " error", e);
				throw new NetworkException("Network error.", e);
			}
		}
	}

    /**
     * Set DIDAdapter for DIDBackend.
     *
     * @param adapter the DIDAdapter object
     */
	private DIDBackend(DIDAdapter adapter) {
		this.adapter = adapter;
	}

	/**
	 * Initialize DIDBackend to resolve by url and cache path stored the document in ttl time.
	 * Recommendation for cache dir:
	 * - Laptop/standard Java
	 *   System.getProperty("user.home") + "/.cache.did.elastos"
	 * - Android Java
	 *   Context.getFilesDir() + "/.cache.did.elastos"
	 *
	 * @param resolverURL the url string to resolve did
	 * @param cacheDir the cache path to store did document
	 * @throws DIDResolveException throw this exception if initializing backend failed with
	 *         creating DIDResolver error.
	 */
	public static void initialize(String resolverURL, File cacheDir)
			throws DIDResolveException {
		if (resolverURL == null || resolverURL.isEmpty() || cacheDir == null)
			throw new IllegalArgumentException();

		initialize(new DefaultResolver(resolverURL), cacheDir);
	}

	/**
	 * Initialize DIDBackend to resolve by url string and cache path stored the document in ttl time.
	 * Recommendation for cache dir:
	 * - Laptop/standard Java
	 *   System.getProperty("user.home") + "/.cache.did.elastos"
	 * - Android Java
	 *   Context.getFilesDir() + "/.cache.did.elastos"
	 *
	 * @param resolverURL the url string to resolve did
	 * @param cacheDir the cache path to store did document
	 * @throws DIDResolveException throw this exception if initializing backend failed with
	 *         creating DIDResolver error.
	 **/
	public static void initialize(String resolverURL, String cacheDir)
			throws DIDResolveException {
		if (resolverURL == null || resolverURL.isEmpty() ||
				cacheDir == null || cacheDir.isEmpty())
			throw new IllegalArgumentException();

		initialize(resolverURL, new File(cacheDir));
	}

    /**
	 * Initialize DIDBackend to resolve by url string and cache path stored the document in ttl time.
	 * Recommendation for cache dir:
	 * - Laptop/standard Java
	 *   System.getProperty("user.home") + "/.cache.did.elastos"
	 * - Android Java
	 *   Context.getFilesDir() + "/.cache.did.elastos"
     *
     * @param resolver the DIDResolver object
     * @param cacheDir the cache path name
     */
	public static void initialize(DIDResolver resolver, File cacheDir) {
		if (resolver == null || cacheDir == null)
			throw new IllegalArgumentException();

		DIDBackend.resolver = resolver;
		ResolverCache.setCacheDir(cacheDir);
	}

    /**
	 * Initialize DIDBackend to resolve by url string and cache path stored the document in ttl time.
	 * Recommendation for cache dir:
	 * - Laptop/standard Java
	 *   System.getProperty("user.home") + "/.cache.did.elastos"
	 * - Android Java
	 *   Context.getFilesDir() + "/.cache.did.elastos"
     *
     * @param resolver the DIDResolver object
     * @param cacheDir the cache path name
     */
	public static void initialize(DIDResolver resolver, String cacheDir) {
		if (resolver == null || cacheDir == null || cacheDir.isEmpty())
			throw new IllegalArgumentException();

		initialize(resolver, new File(cacheDir));
	}

	/**
	 * Get DIDBackend instance according to specified DIDAdapter object.
	 *
	 * @param adapter the DIDAdapter object
	 * @return the DIDBackend instance
	 */
	protected static DIDBackend getInstance(DIDAdapter adapter) {
		return new DIDBackend(adapter);
	}

	/**
	 * Set the cache time to live in minutes.
	 *
	 * @param ttl the validate time to store content
	 */
	public static void setTTL(long ttl) {
		ttl = ttl > 0 ? (ttl * 60 * 1000) : 0;
	}

	/**
	 * Get the cache time to live in minutes.
	 *
	 * @return the validate time to live
	 */
	public static long getTTL() {
		return ttl != 0 ? (ttl / 60 / 1000) : 0;
	}

	private static String generateRequestId() {
		StringBuffer sb = new StringBuffer();

		while(sb.length() < 16)
			sb.append(Integer.toHexString(random.nextInt()));

		return sb.toString();
	}

	/**
     * Set DID Local Resolve handle in order to give the method handle which did document to verify.
     * If handle != NULL, set DID Local Resolve Handle; If handle == NULL, clear this handle.
     *
	 * @param handle the ResolveHandle object
	 */
	public static void setResolveHandle(ResolveHandle handle) {
		DIDBackend.resolveHandle = handle;
	}

	private static ResolveResult resolveFromBackend(DID did, boolean all)
			throws DIDResolveException {
		if (resolver == null)
			throw new DIDResolveException("DID resolver not initialized.");

		String requestId = generateRequestId();
		InputStream is = resolver.resolve(requestId, did.toString(), all);
		ResolveResponse response;
		try {
			response = ResolveResponse.parse(is, ResolveResponse.class);
		} catch (DIDSyntaxException | IOException e) {
			throw new DIDResolveException(e);
		} finally {
			try {
				is.close();
			} catch (IOException ignore) {
			}
		}

		if (response.getId() == null || !response.getId().equals(requestId))
			throw new DIDResolveException("Mismatched resolve result with request.");

		ResolveResult rr = response.getResult();
		if (rr == null) {
			throw new DIDResolveException("Resolve DID error("
					+ response.getErrorCode() + "): " + response.getErrorMessage());
		}

		if (rr.getStatus() != ResolveResult.STATUS_NOT_FOUND) {
			try {
				ResolverCache.store(rr);
			} catch (IOException e) {
				System.out.println("!!! Cache resolved resolved result error: "
						+ e.getMessage());
			}
		}

		return rr;
	}

    /**
     * Resolve all DID transactions.
     *
     * @param did the specified DID object
     * @return the ResolveResult object
     * @throws DIDResolveException throw this exception if resolving did transcations failed.
     */
	protected static ResolveResult resolveHistory(DID did) throws DIDResolveException {
		log.info("Resolving {}...", did.toString());

		ResolveResult rr = resolveFromBackend(did, true);
		if (rr.getStatus() == ResolveResult.STATUS_NOT_FOUND)
			return null;

		return rr;
	}

	/**
	 * Resolve DID content(DIDDocument).
	 *
	 * @param did the DID object
	 * @param force force = true, DID content must be from chain.
	 *              force = false, DID content could be from chain or local cache.
	 * @return the DIDDocument object
	 * @throws DIDResolveException throw this exception if resolving did failed.
	 */
	protected static DIDDocument resolve(DID did, boolean force)
			throws DIDResolveException {
		log.info("Resolving {}...", did.toString());

		if (DIDBackend.resolveHandle != null) {
			DIDDocument doc = resolveHandle.resolve(did);
			if (doc != null)
				return doc;
		}

		ResolveResult rr = null;
		if (!force) {
			rr = ResolverCache.load(did, ttl);
			log.debug("Try load {} from resolver cache: {}.",
					did.toString(), rr == null ? "non" : "matched");
		}

		if (rr == null)
			rr = resolveFromBackend(did, false);

		switch (rr.getStatus()) {
		// When DID expired, we should also return the document.
		// case ResolveResult.STATUS_EXPIRED:
		// 	throw new DIDExpiredException();

		case ResolveResult.STATUS_DEACTIVATED:
			throw new DIDDeactivatedException();

		case ResolveResult.STATUS_NOT_FOUND:
			return null;

		default:
			IDChainTransaction tx = rr.getTransaction(0);

			try {
				if (!tx.getRequest().isValid())
					throw new DIDResolveException("Invalid ID transaction, signature mismatch.");
			} catch (DIDTransactionException | DIDResolveException e) {
				throw new DIDResolveException("Can not verify the transaction", e);
			}

			DIDDocument doc = tx.getRequest().getDocument();
			DIDMetadata metadata = new DIDMetadata();
			metadata.setTransactionId(tx.getTransactionId());
			metadata.setSignature(doc.getProof().getSignature());
			metadata.setPublished(tx.getTimestamp());
			metadata.setLastModified(tx.getTimestamp());
			doc.setMetadata(metadata);
			return doc;
		}
	}

	/**
	 * Resolve DID content(DIDDocument).
	 *
	 * @param did the DID object
	 * @return the DIDDocument object
	 * @throws DIDResolveException throw this exception if resolving did failed.
	 */
	protected static DIDDocument resolve(DID did) throws DIDResolveException {
		return resolve(did, false);
	}

	/**
	 * Get DIDAdapter object.
	 *
	 * @return the DIDAdapter object from DIDBackend.
	 */
	protected DIDAdapter getAdapter() {
		return adapter;
	}

	private void createTransaction(String payload, String memo)
			throws DIDTransactionException {
		log.info("Create ID transaction...");
		log.trace("Transaction paload: '{}', memo: {}", payload, memo);

		adapter.createIdTransaction(payload, memo);

		log.info("ID transaction complete.");
	}

	/**
	 * Publish 'create' id transaction for the new did.
	 *
	 * @param doc the DIDDocument object
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @throws DIDTransactionException publishing did failed because of did transaction error.
	 * @throws DIDStoreException did document does not attach store or there is no sign key to get.
	 * @throws InvalidKeyException sign key is not an authentication key if sign key exists.
	 */
	protected void create(DIDDocument doc, DIDURL signKey, String storepass)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		IDChainRequest request = IDChainRequest.create(doc, signKey, storepass);
		String json = request.toString(true);
		createTransaction(json, null);
	}

	/**
	 * Publish 'Update' id transaction for the existed did.
	 *
	 * @param doc the DIDDocument object
	 * @param previousTxid the previous transaction id string
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
	 * @throws DIDTransactionException publishing did failed because of did transaction error.
	 * @throws DIDStoreException did document does not attach store or there is no sign key to get.
	 * @throws InvalidKeyException sign key is not an authentication key if sign key exists.
	 */
	protected void update(DIDDocument doc, String previousTxid,
			DIDURL signKey, String storepass)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		IDChainRequest request = IDChainRequest.update(doc, previousTxid,
				signKey, storepass);
		String json = request.toString(true);
		createTransaction(json, null);
		ResolverCache.invalidate(doc.getSubject());
	}

    /**
     * Publish id transaction to deactivate the existed did.
     *
     * @param doc the DIDDocument object
     * @param signKey the key to sign
     * @param storepass the password for DIDStore
     * @throws DIDTransactionException publishing did failed because of did transaction error.
     * @throws DIDStoreException did document does not attach store or there is no sign key to get.
     * @throws InvalidKeyException sign key is not an authentication key if sign key exists.
     */
	protected void deactivate(DIDDocument doc, DIDURL signKey, String storepass)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		IDChainRequest request = IDChainRequest.deactivate(doc, signKey, storepass);
		String json = request.toString(true);
		createTransaction(json, null);
		ResolverCache.invalidate(doc.getSubject());
	}

	/**
     * Publish id transaction to deactivate the existed did.
	 *
	 * @param target the DID to be deactivated
	 * @param targetSignKey the key to sign of specified DID
	 * @param doc the DIDDocument object
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
     * @throws DIDTransactionException publishing did failed because of did transaction error.
     * @throws DIDStoreException did document does not attach store or there is no sign key to get.
     * @throws InvalidKeyException sign key is not an authentication key if sign key exists.
	 */
	protected void deactivate(DID target, DIDURL targetSignKey,
			DIDDocument doc, DIDURL signKey, String storepass)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		IDChainRequest request = IDChainRequest.deactivate(target,
				targetSignKey, doc, signKey, storepass);
		String json = request.toString(true);
		createTransaction(json, null);
		ResolverCache.invalidate(target);
	}
}
