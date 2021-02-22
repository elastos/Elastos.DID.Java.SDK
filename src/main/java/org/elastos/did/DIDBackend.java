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
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.elastos.did.backend.CredentialBiography;
import org.elastos.did.backend.CredentialList;
import org.elastos.did.backend.CredentialListRequest;
import org.elastos.did.backend.CredentialListResponse;
import org.elastos.did.backend.CredentialRequest;
import org.elastos.did.backend.CredentialResolveRequest;
import org.elastos.did.backend.CredentialResolveResponse;
import org.elastos.did.backend.CredentialTransaction;
import org.elastos.did.backend.DIDBiography;
import org.elastos.did.backend.DIDRequest;
import org.elastos.did.backend.DIDResolveRequest;
import org.elastos.did.backend.DIDResolveResponse;
import org.elastos.did.backend.DIDTransaction;
import org.elastos.did.backend.IDChainRequest;
import org.elastos.did.backend.ResolveRequest;
import org.elastos.did.backend.ResolveResponse;
import org.elastos.did.backend.ResolveResult;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.DIDTransactionException;
import org.elastos.did.exception.InvalidKeyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

/**
 * The class is to provide the backend for resolving DID.
 */
public class DIDBackend {
	private static final int DEFAULT_CACHE_INITIAL_CAPACITY = 16;
	private static final int DEFAULT_CACHE_MAX_CAPACITY = 64;
	private static final int DEFAULT_CACHE_TTL = 10 * 60 * 1000;

	private static Random random = new Random();

	private DIDAdapter adapter;
	private ResolveHandle resolveHandle;

	private LoadingCache<ResolveRequest<?, ?>, ResolveResult<?>> cache;

	private static final Logger log = LoggerFactory.getLogger(DIDBackend.class);

	private static DIDBackend instance;

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

	/**
	 * Create a DIDBackend with the adapter and the cache specification.
     *
     * @param adapter the DIDAdapter object
     * @param initialCacheCapacity the initial cache size, 0 for default size
     * @param maxCacheCapacity the maximum cache capacity, 0 for default capacity
     * @param int cacheTtl the live time for the cached entries, 0 for default
     */
	private DIDBackend(DIDAdapter adapter, int initialCacheCapacity,
			int maxCacheCapacity, int cacheTtl) {
		if (initialCacheCapacity < 0)
			initialCacheCapacity = 0;

		if (maxCacheCapacity < 0)
			maxCacheCapacity = 0;

		if (cacheTtl < 0)
			cacheTtl = 0;

		this.adapter = adapter;

		CacheLoader<ResolveRequest<?, ?>, ResolveResult<?>> loader;
		loader = new CacheLoader<ResolveRequest<?, ?>, ResolveResult<?>>() {
			@Override
			public ResolveResult<?> load(ResolveRequest<?, ?> key)
					throws DIDResolveException {
				log.trace("Cache loading {}...", key);
				return resolve(key);
			}
		};

		// The RemovalListener used for debug purpose.
		/*
		RemovalListener<ResolveRequest<?, ?>, ResolveResult<?>> listener;
		listener = new RemovalListener<ResolveRequest<?, ?>, ResolveResult<?>>() {
			@Override
			public void onRemoval(
					RemovalNotification<ResolveRequest<?, ?>, ResolveResult<?>> n) {
				if (n.wasEvicted()) {
					String cause = n.getCause().name();
					log.trace("Cache removed {} cause {}", n.getKey(), cause);
				}
			}
		};
		*/

		cache = CacheBuilder.newBuilder()
				.initialCapacity(initialCacheCapacity)
				.maximumSize(maxCacheCapacity)
				.expireAfterWrite(cacheTtl, TimeUnit.MILLISECONDS)
				.softValues()
				// .removalListener(listener)
				// .recordStats()
				.build(loader);

		log.info("DID backend initialized, cache(init:{}, max:{}, ttl:{})",
				initialCacheCapacity, maxCacheCapacity, cacheTtl / 1000);
	}

    /**
	 * Initialize the DIDBackend with the adapter and the cache specification.
     *
     * @param adapter the DIDAdapter object
     * @param initialCacheCapacity the initial cache size, 0 for default size
     * @param maxCacheCapacity the maximum cache capacity, 0 for default capacity
     * @param int cacheTtl the live time for the cached entries, 0 for default
     */
	public static synchronized void initialize(DIDAdapter adapter,
			int initialCacheCapacity, int maxCacheCapacity, int cacheTtl) {
		checkArgument(adapter != null, "Invalid adapter");
		//checkArgument(initialCacheCapacity <= maxCacheCapacity, "Invalid cache capacity");

		initialCacheCapacity = initialCacheCapacity < maxCacheCapacity ?
				initialCacheCapacity : maxCacheCapacity;

		instance = new DIDBackend(adapter, initialCacheCapacity,
				maxCacheCapacity, cacheTtl);
	}

    /**
	 * Initialize the DIDBackend with the adapter and the cache specification.
     *
     * @param adapter the DIDAdapter object
     * @param maxCacheCapacity the maximum cache capacity, 0 for default capacity
     * @param int cacheTtl the live time for the cached entries, 0 for default
     */
	public static void initialize(DIDAdapter adapter, int maxCacheCapacity, int cacheTtl) {

		initialize(adapter, DEFAULT_CACHE_INITIAL_CAPACITY, maxCacheCapacity, cacheTtl);
	}

    /**
	 * Initialize the DIDBackend with the adapter and the cache specification.
     *
     * @param adapter the DIDAdapter object
     * @param int cacheTtl the live time for the cached entries, 0 for default
     */
	public static void initialize(DIDAdapter adapter, int cacheTtl) {
		initialize(adapter, DEFAULT_CACHE_INITIAL_CAPACITY,
				DEFAULT_CACHE_MAX_CAPACITY, cacheTtl);
	}

    /**
	 * Initialize the DIDBackend with the adapter.
     *
     * @param adapter the DIDAdapter object
     */
	public static void initialize(DIDAdapter adapter) {
		initialize(adapter, DEFAULT_CACHE_INITIAL_CAPACITY,
				DEFAULT_CACHE_MAX_CAPACITY, DEFAULT_CACHE_TTL);
	}

	/**
	 * Get DIDBackend instance according to specified DIDAdapter object.
	 *
	 * @return the DIDBackend instance
	 */
	public static DIDBackend getInstance() {
		return instance;
	}

	private String generateRequestId() {
		StringBuffer sb = new StringBuffer();

		while(sb.length() < 16)
			sb.append(Integer.toHexString(random.nextInt()));

		return sb.toString();
	}

	/**
	 * Get DIDAdapter object.
	 *
	 * @return the DIDAdapter object from DIDBackend.
	 */
	protected DIDAdapter getAdapter() {
		return adapter;
	}

	/**
     * Set DID Local Resolve handle in order to give the method handle which did document to verify.
     * If handle != NULL, set DID Local Resolve Handle; If handle == NULL, clear this handle.
     *
	 * @param handle the ResolveHandle object
	 */
	public void setResolveHandle(ResolveHandle handle) {
		resolveHandle = handle;
	}

	private ResolveResult<?> resolve(ResolveRequest<?, ?> request)
			throws DIDResolveException {
		log.debug("Resolving request {}...", request);

		String requestJson = null;
		try {
			requestJson = request.serialize(true);
		} catch (DIDSyntaxException e) {
			log.error("INTERNAL - Serialize resolve request", e);
			throw new DIDResolveException("Can not serialize the request", e);
		}

		InputStream is = getAdapter().resolve(requestJson);

		ResolveResponse<?, ?> response = null;
		try {
			switch (request.getMethod()) {
			case DIDResolveRequest.METHOD_NAME:
				response = DIDResolveResponse.parse(is, DIDResolveResponse.class);
				break;

			case CredentialResolveRequest.METHOD_NAME:
				response = CredentialResolveResponse.parse(is, CredentialResolveResponse.class);
				break;

			case CredentialListRequest.METHOD_NAME:
				response = CredentialListResponse.parse(is, CredentialListResponse.class);
				break;

			default:
				log.error("INTERNAL - unknown resolve method '{}'", request.getMethod());
				throw new DIDResolveException("Unknown resolve method: " + request.getMethod());
			}
		} catch (DIDSyntaxException | IOException e) {
			throw new DIDResolveException(e);
		} finally {
			try {
				is.close();
			} catch (IOException ignore) {
			}
		}

		if (response.getResponseId() == null ||
				!response.getResponseId().equals(request.getRequestId()))
			throw new DIDResolveException("Mismatched resolve result with request.");

		if (response.getResult() != null)
			return response.getResult();
		else
			throw new DIDResolveException("Server error(" + response.getErrorCode()
					+ "): " + response.getErrorMessage());
	}

	private DIDBiography resolveDidBiography(DID did, boolean all, boolean force)
			throws DIDResolveException {
		log.info("Resolving DID {}, all={}...", did.toString(), all);

		DIDResolveRequest request = new DIDResolveRequest(generateRequestId());
		request.setParameters(did, all);

		if (force)
			cache.invalidate(request);

		try {
			return (DIDBiography)cache.get(request);
		} catch (ExecutionException e) {
			throw new DIDResolveException(e);
		}
	}

    /**
     * Resolve all DID transactions.
     *
     * @param did the specified DID object
     * @return the DIDBiography object
     * @throws DIDResolveException throw this exception if resolving did transcations failed.
     */
	protected DIDBiography resolveDidBiography(DID did) throws DIDResolveException {
		DIDBiography rr = resolveDidBiography(did, true, false);
		if (rr.getStatus() == DIDBiography.Status.NOT_FOUND)
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
	protected DIDDocument resolveDid(DID did, boolean force)
			throws DIDResolveException {
		log.debug("Resolving DID {}...", did.toString());

		if (resolveHandle != null) {
			DIDDocument doc = resolveHandle.resolve(did);
			if (doc != null)
				return doc;
		}

		DIDBiography bio = resolveDidBiography(did, false, force);

		DIDTransaction tx = null;
		switch (bio.getStatus()) {
		case VALID:
			tx = bio.getTransaction(0);
			break;

		case DEACTIVATED:
			if (bio.getTransactionCount() != 2)
				throw new DIDResolveException("Invalid DID biography, wrong transaction count.");

			tx = bio.getTransaction(0);
			if (tx.getRequest().getOperation() != IDChainRequest.Operation.DEACTIVATE)
				throw new DIDResolveException("Invalid DID biography, wrong status.");

			DIDDocument doc = bio.getTransaction(1).getRequest().getDocument();
			if (doc == null)
				throw new DIDResolveException("Invalid DID biography, invalid trancations.");

			// Avoid resolve current DID recursively
			DIDRequest request = new DIDRequest(tx.getRequest()) {
				@Override
				protected DIDDocument getSignerDocument() throws DIDResolveException {
					return getDocument() == null ? doc : getDocument();
				}
			};

			if (!request.isValid())
				throw new DIDResolveException("Invalid DID biography, transaction signature mismatch.");

			tx = bio.getTransaction(1);
			break;

		case NOT_FOUND:
			return null;
		}

		if (tx.getRequest().getOperation() != IDChainRequest.Operation.CREATE &&
				tx.getRequest().getOperation() != IDChainRequest.Operation.UPDATE &&
				tx.getRequest().getOperation() != IDChainRequest.Operation.TRANSFER)
			throw new DIDResolveException("Invalid ID transaction, unknown operation.");

		if (!tx.getRequest().isValid())
			throw new DIDResolveException("Invalid ID transaction, signature mismatch.");

		DIDDocument doc = tx.getRequest().getDocument();
		DIDMetadata metadata = new DIDMetadata(doc.getSubject());
		metadata.setTransactionId(tx.getTransactionId());
		metadata.setSignature(doc.getProof().getSignature());
		metadata.setPublished(tx.getTimestamp());
		if (bio.getStatus() == DIDBiography.Status.DEACTIVATED)
			metadata.setDeactivated(true);
		doc.setMetadata(metadata);
		return doc;
	}

	/**
	 * Resolve DID content(DIDDocument).
	 *
	 * @param did the DID object
	 * @return the DIDDocument object
	 * @throws DIDResolveException throw this exception if resolving did failed.
	 */
	protected DIDDocument resolveDid(DID did) throws DIDResolveException {
		return resolveDid(did, false);
	}

	private CredentialBiography resolveCredentialBiography(DIDURL id, DID issuer, boolean force)
			throws DIDResolveException {
		log.info("Resolving credential {}, issuer={}...", id, issuer);

		CredentialResolveRequest request = new CredentialResolveRequest(generateRequestId());
		request.setParameters(id, issuer);

		if (force)
			cache.invalidate(request);

		try {
			return (CredentialBiography)cache.get(request);
		} catch (ExecutionException e) {
			throw new DIDResolveException(e);
		}
	}

	protected CredentialBiography resolveCredentialBiography(DIDURL id, DID issuer)
			throws DIDResolveException {
		return resolveCredentialBiography(id, issuer, false);
	}

	protected CredentialBiography resolveCredentialBiography(DIDURL id)
			throws DIDResolveException {
		return resolveCredentialBiography(id, null, false);
	}

	protected VerifiableCredential resolveCredential(DIDURL id, DID issuer, boolean force)
			throws DIDResolveException {
		log.debug("Resolving credential {}...", id);

		CredentialBiography bio = resolveCredentialBiography(id, issuer, force);

		CredentialTransaction tx = null;
		switch (bio.getStatus()) {
		case VALID:
			tx = bio.getTransaction(0);
			break;

		case REVOKED:
			tx = bio.getTransaction(0);
			if (tx.getRequest().getOperation() != IDChainRequest.Operation.REVOKE)
				throw new DIDResolveException("Invalid credential biography, wrong status.");

			if (bio.getTransactionCount() < 1 || bio.getTransactionCount() > 2)
				throw new DIDResolveException("Invalid credential biography, transaction signature mismatch.");


			if (bio.getTransactionCount() == 1) {
				if (!tx.getRequest().isValid())
					throw new DIDResolveException("Invalid credential biography, transaction signature mismatch.");

				return null;
			} else {
				VerifiableCredential vc = bio.getTransaction(1).getRequest().getCredential();

				// Avoid resolve current credential recursively
				CredentialRequest request = new CredentialRequest(tx.getRequest()) {
					@Override
					public VerifiableCredential getCredential() {
						return vc;
					}
				};


				if (!request.isValid())
					throw new DIDResolveException("Invalid credential biography, transaction signature mismatch.");
			}

			tx = bio.getTransaction(1);
			break;

		case NOT_FOUND:
			return null;
		}

		if (tx.getRequest().getOperation() != IDChainRequest.Operation.DECLARE)
			throw new DIDResolveException("Invalid credential transaction, unknown operation.");

		if (!tx.getRequest().isValid())
			throw new DIDResolveException("Invalid credential transaction, signature mismatch.");

		VerifiableCredential vc = tx.getRequest().getCredential();
		CredentialMetadata metadata = new CredentialMetadata(vc.getId());
		metadata.setTransactionId(tx.getTransactionId());
		metadata.setPublished(tx.getTimestamp());
		if (bio.getStatus() == CredentialBiography.Status.REVOKED)
			metadata.setRevoked(true);
		vc.setMetadata(metadata);
		return vc;
	}

	protected VerifiableCredential resolveCredential(DIDURL id, DID issuer)
			throws DIDResolveException {
		return resolveCredential(id, issuer, false);
	}

	protected VerifiableCredential resolveCredential(DIDURL id, boolean force)
			throws DIDResolveException {
		return resolveCredential(id, null, force);
	}

	protected VerifiableCredential resolveCredential(DIDURL id)
			throws DIDResolveException {
		return resolveCredential(id, null, false);
	}

	protected List<DIDURL> listCredentials(DID did, int skip, int limit)
			throws DIDResolveException {
		log.info("List credentials for {}", did);

		CredentialListRequest request = new CredentialListRequest(generateRequestId());
		request.setParameters(did, skip, limit);

		CredentialList list = (CredentialList)resolve(request);
		if (list == null || list.size() == 0)
			return null;

		return list.getCredentialIds();
	}

	private void createTransaction(IDChainRequest<?> request,
			DIDTransactionAdapter adapter) throws DIDTransactionException {
		log.info("Create ID transaction...");

		try {
			String payload = request.serialize(true);
			log.trace("Transaction paload: '{}', memo: {}", payload, "");

			if (adapter == null)
				adapter = getAdapter();

			adapter.createIdTransaction(payload, payload);
		} catch (DIDSyntaxException e) {
			log.error("INTERNAL - Serialize IDChainRequest failed", e);
			throw new DIDTransactionException("Serialize IDChainRequest failed", e);
		}

		log.info("ID transaction complete.");
	}

	private void invalidDidCache(DID did) {
		DIDResolveRequest request = new DIDResolveRequest(generateRequestId());
		request.setParameters(did, true);
		cache.invalidate(request);

		request.setParameters(did, false);
		cache.invalidate(request);
	}

	private void invalidCredentialCache(DIDURL id, DID signer) {
		CredentialResolveRequest request = new CredentialResolveRequest(generateRequestId());
		request.setParameters(id, signer);
		cache.invalidate(request);
	}

	public void clearCache() {
		cache.invalidateAll();
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
	protected void createDid(DIDDocument doc, DIDURL signKey,
			String storepass, DIDTransactionAdapter adapter)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		DIDRequest request = DIDRequest.create(doc, signKey, storepass);
		createTransaction(request, adapter);
		invalidDidCache(doc.getSubject());
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
	protected void updateDid(DIDDocument doc, String previousTxid,
			DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		DIDRequest request = DIDRequest.update(doc, previousTxid, signKey, storepass);
		createTransaction(request, adapter);
		invalidDidCache(doc.getSubject());
	}

	protected void transferDid(DIDDocument doc, TransferTicket ticket,
			DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, InvalidKeyException, DIDTransactionException {
		DIDRequest request = DIDRequest.transfer(doc, ticket, signKey, storepass);
		createTransaction(request, adapter);
		invalidDidCache(doc.getSubject());
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
	protected void deactivateDid(DIDDocument doc, DIDURL signKey,
			String storepass, DIDTransactionAdapter adapter)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		DIDRequest request = DIDRequest.deactivate(doc, signKey, storepass);
		createTransaction(request, adapter);
		invalidDidCache(doc.getSubject());
	}

	/**
     * Publish id transaction to deactivate the existed did.
	 *
	 * @param target the DID to be deactivated
	 * @param targetSignKey the key to sign of specified DID
	 * @param signer the signer's DIDDocument object
	 * @param signKey the key to sign
	 * @param storepass the password for DIDStore
     * @throws DIDResolveException publishing did failed because of resolve target did error.
     * @throws DIDTransactionException publishing did failed because of did transaction error.
     * @throws DIDStoreException did document does not attach store or there is no sign key to get.
     * @throws InvalidKeyException sign key is not an authentication key if sign key exists.
	 */
	protected void deactivateDid(DIDDocument target, DIDURL targetSignKey,
			DIDDocument signer, DIDURL signKey, String storepass,
			DIDTransactionAdapter adapter)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		DIDRequest request = DIDRequest.deactivate(target,
				targetSignKey, signer, signKey, storepass);
		createTransaction(request, adapter);
		invalidDidCache(target.getSubject());
	}

	protected void declareCredential(VerifiableCredential vc, DIDDocument signer,
			DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		CredentialRequest request = CredentialRequest.declare(vc, signer,
				signKey, storepass);
		createTransaction(request, adapter);
		invalidCredentialCache(vc.getId(), null);
		invalidCredentialCache(vc.getId(), vc.getIssuer());
	}

	protected void revokeCredential(VerifiableCredential vc, DIDDocument signer,
			DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		CredentialRequest request = CredentialRequest.revoke(vc, signer,
				signKey, storepass);
		createTransaction(request, adapter);
		invalidCredentialCache(vc.getId(), null);
		invalidCredentialCache(vc.getId(), vc.getIssuer());
	}

	protected void revokeCredential(DIDURL vc, DIDDocument signer,
			DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		CredentialRequest request = CredentialRequest.revoke(vc, signer,
				signKey, storepass);
		createTransaction(request, adapter);
		invalidCredentialCache(vc, null);
		invalidCredentialCache(vc, signer.getSubject());
	}
}
