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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

/**
 * The class is an abstraction for the ID chain.
 */
public class DIDBackend {
	/**
	 * The default initial capacity for the resolve cache.
	 */
	public static final int DEFAULT_CACHE_INITIAL_CAPACITY = 16;
	/**
	 * The default maximum capacity for the resolve cache.
	 */
	public static final int DEFAULT_CACHE_MAX_CAPACITY = 64;
	/**
	 * The default cache TTL.
	 */
	public static final int DEFAULT_CACHE_TTL = 10 * 60 * 1000;

	private static Random random = new Random();

	private DIDAdapter adapter;
	private LocalResolveHandle resolveHandle;

	private LoadingCache<ResolveRequest<?, ?>, ResolveResult<?>> cache;

	private static final Logger log = LoggerFactory.getLogger(DIDBackend.class);

	private static DIDBackend instance;

	/**
	 * The interface is used to provide local resolve capability to the DID SDK.
	 */
	@FunctionalInterface
	public interface LocalResolveHandle {
		/**
		 * Resolve the DIDDocument for the specific DID.
		 *
		 * @param did the DID to be resolve
		 * @return the DIDDocument object
		 */
		public DIDDocument resolve(DID did);
	}

	/**
	 * Construct a DIDBackend instance with the adapter and the cache
	 * specification.
	 *
	 * @param adapter a DIDAdapter implementation
	 * @param initialCacheCapacity the initial cache size
	 * @param maxCacheCapacity the maximum cache capacity
	 * @param cacheTtl the live time for the cached entries
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

	/*
	public String cacheStat() {
		return cache.stats().toString();
	}
	*/

	/**
	 * Initialize the DIDBackend with the given adapter and the cache
	 * specification.
	 *
	 * @param adapter a DIDAdapter implementation
	 * @param initialCacheCapacity the initial cache size
	 * @param maxCacheCapacity the maximum cache capacity
	 * @param cacheTtl the live time for the cached entries
	 */
	public static synchronized void initialize(DIDAdapter adapter,
			int initialCacheCapacity, int maxCacheCapacity, int cacheTtl) {
		checkArgument(adapter != null, "Invalid adapter");
		checkArgument(initialCacheCapacity <= maxCacheCapacity, "Invalid cache capacity");

		initialCacheCapacity = initialCacheCapacity < maxCacheCapacity ?
				initialCacheCapacity : maxCacheCapacity;

		instance = new DIDBackend(adapter, initialCacheCapacity,
				maxCacheCapacity, cacheTtl);
	}

	/**
	 * Initialize the DIDBackend with the given adapter and the cache
	 * specification.
	 *
	 * @param adapter a DIDAdapter implementation
	 * @param maxCacheCapacity the maximum cache capacity
	 * @param cacheTtl the live time for the cached entries
	 */
	public static void initialize(DIDAdapter adapter, int maxCacheCapacity, int cacheTtl) {
		initialize(adapter, DEFAULT_CACHE_INITIAL_CAPACITY, maxCacheCapacity, cacheTtl);
	}

	/**
	 * Initialize the DIDBackend with the given adapter and the cache
	 * specification.
	 *
	 * @param adapter a DIDAdapter implementation
	 * @param cacheTtl the live time for the cached entries
	 */
	public static void initialize(DIDAdapter adapter, int cacheTtl) {
		initialize(adapter, DEFAULT_CACHE_INITIAL_CAPACITY,
				DEFAULT_CACHE_MAX_CAPACITY, cacheTtl);
	}

	/**
	 * Initialize the DIDBackend with the given adapter and the default cache
	 * specification.
	 *
	 * @param adapter a DIDAdapter implementation
	 */
	public static void initialize(DIDAdapter adapter) {
		initialize(adapter, DEFAULT_CACHE_INITIAL_CAPACITY,
				DEFAULT_CACHE_MAX_CAPACITY, DEFAULT_CACHE_TTL);
	}

	/**
	 * Check if the DIDBackend already initialized.
	 *
	 * @return the DIDBackend initialized or not
	 */
	public static boolean isInitialized() {
		return instance != null;
	}

	/**
	 * Get the previous initialized DIDBackend instance.
	 *
	 * @return the DIDBackend instance
	 */
	public static DIDBackend getInstance() {
		if (instance == null)
			throw new IllegalStateException("DIDBackend not initialized.");

		return instance;
	}

	private String generateRequestId() {
		byte[] bin = new byte[16];
		random.nextBytes(bin);
		return Hex.toHexString(bin);
	}

	private DIDAdapter getAdapter() {
		return adapter;
	}

	/**
	 * Set a local resolve handle for DID local resolving.
	 *
	 * <p>
	 * The DIDBackend instance will remove the previous installed handle if
	 * the handle is NULL, replace the previous handle otherwise.
	 * </p>
	 *
	 * @param handle a ResolveHandle instance
	 */
	public void setResolveHandle(LocalResolveHandle handle) {
		resolveHandle = handle;
	}

	private ResolveResult<?> resolve(ResolveRequest<?, ?> request)
			throws DIDResolveException {
		log.debug("Resolving request {}...", request);

		String requestJson = request.serialize(true);
		InputStream is = getAdapter().resolve(requestJson);
		if (is == null)
			throw new DIDResolveException("Unknown error, got null result.");

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
	 * Resolve all transactions for a specific DID.
	 *
	 * @param did the DID object to be resolve
	 * @return the DIDBiography object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
	protected DIDBiography resolveDidBiography(DID did) throws DIDResolveException {
		DIDBiography rr = resolveDidBiography(did, true, false);
		if (rr.getStatus() == DIDBiography.Status.NOT_FOUND)
			return null;

		return rr;
	}

	/**
	 * Resolve the specific DID.
	 *
	 * @param did the DID object to be resolve
	 * @param force ignore the local cache and resolve from the ID chain if true;
	 * 		  		try to use cache first if false.
	 * @return the DIDDocument object
	 * @throws DIDResolveException if an error occurred when resolving DID
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
			if (bio.size() != 2)
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

		// NOTICE: Make a copy from DIDBackend cache.
		// 		   Avoid share same DIDDocument instance between DIDBackend
		//         cache and DIDStore cache.
		DIDDocument doc = tx.getRequest().getDocument().clone();
		DIDMetadata metadata = doc.getMetadata();
		metadata.setTransactionId(tx.getTransactionId());
		metadata.setSignature(doc.getProof().getSignature());
		metadata.setPublishTime(tx.getTimestamp());
		if (bio.getStatus() == DIDBiography.Status.DEACTIVATED)
			metadata.setDeactivated(true);

		return doc;
	}

	/**
	 * Resolve the specific DID.
	 *
	 * @param did the DID object to be resolve
	 * @return the DIDDocument object
	 * @throws DIDResolveException if an error occurred when resolving DID
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

	/**
	 * Resolve the all the credential transactions.
	 *
	 * <p>
	 * If the credential already declared on the ID chain, this method will
	 * return all credential transactions include the revoke transaction.
	 * The issuer parameter will be ignored in this case.
	 * </p>
	 *
	 * <p>
	 * If the credential not declared on the ID chain, this method will
	 * return the revoke transactions from the credential owner if it exists;
	 * If an issuer DID is given, this method also will return the revoke
	 * transactions from the given issuer if it exists
	 * </p>
	 *
	 * @param id the credential id
	 * @param issuer an optional issuer'd DID
	 * @return a CredentialBiography object
	 * @throws DIDResolveException if an error occurred when resolving the credential
	 */
	protected CredentialBiography resolveCredentialBiography(DIDURL id, DID issuer)
			throws DIDResolveException {
		return resolveCredentialBiography(id, issuer, false);
	}

	/**
	 * Resolve the all the credential transactions.
	 *
	 * <p>
	 * If the credential already declared on the ID chain, this method will
	 * return all credential transactions include the revoke transaction.
	 * </p>
	 *
	 * <p>
	 * If the credential not declared on the ID chain, this method will
	 * return the revoke transactions from the credential owner if it exists.
	 * </p>
	 *
	 * @param id the credential id
	 * @return a CredentialBiography object
	 * @throws DIDResolveException if an error occurred when resolving the credential
	 */
	protected CredentialBiography resolveCredentialBiography(DIDURL id)
			throws DIDResolveException {
		return resolveCredentialBiography(id, null, false);
	}

	/**
	 * Resolve the specific credential.
	 *
	 * @param id the credential id
	 * @param issuer an optional issuer'd DID
	 * @param force ignore the local cache and resolve from the ID chain if true;
	 * 		  		try to use cache first if false.
	 * @return the VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving the credential
	 */
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

			if (bio.size() < 1 || bio.size() > 2)
				throw new DIDResolveException("Invalid credential biography, transaction signature mismatch.");

			if (bio.size() == 1) {
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
		if (!vc.hasMetadata()) {
			CredentialMetadata metadata = new CredentialMetadata(vc.getId());
			metadata.setTransactionId(tx.getTransactionId());
			metadata.setPublishTime(tx.getTimestamp());
			if (bio.getStatus() == CredentialBiography.Status.REVOKED)
				metadata.setRevoked(true);
			vc.setMetadata(metadata);
		}
		return vc;
	}

	/**
	 * Resolve the specific credential.
	 *
	 * @param id the credential id
	 * @param issuer an optional issuer'd DID
	 * @return the VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving the credential
	 */
	protected VerifiableCredential resolveCredential(DIDURL id, DID issuer)
			throws DIDResolveException {
		return resolveCredential(id, issuer, false);
	}

	/**
	 * Resolve the specific credential.
	 *
	 * @param id the credential id
	 * @param force ignore the local cache and resolve from the ID chain if true;
	 * 		  		try to use cache first if false.
	 * @return the VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving the credential
	 */
	protected VerifiableCredential resolveCredential(DIDURL id, boolean force)
			throws DIDResolveException {
		return resolveCredential(id, null, force);
	}

	/**
	 * Resolve the specific credential.
	 *
	 * @param id the credential id
	 * @return the VerifiableCredential object
	 * @throws DIDResolveException if an error occurred when resolving the credential
	 */
	protected VerifiableCredential resolveCredential(DIDURL id)
			throws DIDResolveException {
		return resolveCredential(id, null, false);
	}

	/**
	 * List the declared credentials that owned by the specific DID from
	 * the ID chain.
	 *
	 * @param did the target DID
	 * @param skip set to skip N credentials ahead in this request
	 * 		  (useful for pagination).
	 * @param limit set the limit of credentials returned in the request
	 * 		  (useful for pagination).
	 * @return an array of DIDURL denoting the credentials
	 * @throws DIDResolveException
	 */
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

		String payload = request.serialize(true);
		log.trace("Transaction paload: '{}', memo: {}", payload, "");

		if (adapter == null)
			adapter = getAdapter();

		adapter.createIdTransaction(payload, null);

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

		if (signer != null) {
			request.setParameters(id, null);
			cache.invalidate(request);
		}
	}

	/**
	 * Clear all data that cached by this DIDBackend instance.
	 */
	public void clearCache() {
		cache.invalidateAll();
	}

	/**
	 * Publish a new DID creation transaction to the ID chain.
	 *
	 * @param doc the DIDDocument object to be publish
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for DIDStore
	 * @param adapter a DIDTransactionAdapter instance or null for default
	 * @throws DIDTransactionException if an error when publish the transaction
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected void createDid(DIDDocument doc, DIDURL signKey,
			String storepass, DIDTransactionAdapter adapter)
			throws DIDTransactionException, DIDStoreException {
		DIDRequest request = DIDRequest.create(doc, signKey, storepass);
		createTransaction(request, adapter);
		invalidDidCache(doc.getSubject());
	}

	/**
	 * Publish a DID update transaction to the ID chain.
	 *
	 * @param doc the DIDDocument object to be update
	 * @param previousTxid the previous transaction id string
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for DIDStore
	 * @param adapter a DIDTransactionAdapter instance or null for default
	 * @throws DIDTransactionException if an error when publish the transaction
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected void updateDid(DIDDocument doc, String previousTxid,
			DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDTransactionException, DIDStoreException {
		DIDRequest request = DIDRequest.update(doc, previousTxid, signKey, storepass);
		createTransaction(request, adapter);
		invalidDidCache(doc.getSubject());
	}

	/**
	 * Publish a customized DID transfer transaction to the ID chain.
	 *
	 * @param doc the new DIDDocument object after transfer
	 * @param ticket the valid TransferTicket object
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for DIDStore
	 * @param adapter a DIDTransactionAdapter instance or null for default
	 * @throws DIDTransactionException if an error when publish the transaction
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected void transferDid(DIDDocument doc, TransferTicket ticket,
			DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDStoreException, DIDTransactionException {
		DIDRequest request = DIDRequest.transfer(doc, ticket, signKey, storepass);
		createTransaction(request, adapter);
		invalidDidCache(doc.getSubject());
	}

	/**
	 * Publish a DID deactivate transaction to the ID chain.
	 *
	 * @param doc the DIDDocument object to be deactivate
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for DIDStore
	 * @param adapter a DIDTransactionAdapter instance or null for default
	 * @throws DIDTransactionException if an error when publish the transaction
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected void deactivateDid(DIDDocument doc, DIDURL signKey,
			String storepass, DIDTransactionAdapter adapter)
			throws DIDTransactionException, DIDStoreException {
		DIDRequest request = DIDRequest.deactivate(doc, signKey, storepass);
		createTransaction(request, adapter);
		invalidDidCache(doc.getSubject());
	}

	/**
	 * Publish a DID deactivate transaction to the ID chain.
	 *
	 * @param target the target DIDDocument object to be deactivate
	 * @param targetSignKey the authorization key of the target DIDDocument
	 * @param signer the authorized DID document by the target DID
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for DIDStore
	 * @param adapter a DIDTransactionAdapter instance or null for default
	 * @throws DIDTransactionException if an error when publish the transaction
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected void deactivateDid(DIDDocument target, DIDURL targetSignKey,
			DIDDocument signer, DIDURL signKey, String storepass,
			DIDTransactionAdapter adapter)
			throws DIDTransactionException, DIDStoreException {
		DIDRequest request = DIDRequest.deactivate(target,
				targetSignKey, signer, signKey, storepass);
		createTransaction(request, adapter);
		invalidDidCache(target.getSubject());
	}

	/**
	 * Publish a credential declare transaction to the ID chain.
	 *
	 * @param vc a VerifiableCredential object to be declared
	 * @param signer the credential controller's DIDDocument
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for DIDStore
	 * @param adapter a DIDTransactionAdapter instance or null for default
	 * @throws DIDTransactionException if an error when publish the transaction
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected void declareCredential(VerifiableCredential vc, DIDDocument signer,
			DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDTransactionException, DIDStoreException {
		CredentialRequest request = CredentialRequest.declare(vc, signer,
				signKey, storepass);
		createTransaction(request, adapter);
		invalidCredentialCache(vc.getId(), null);
		invalidCredentialCache(vc.getId(), vc.getIssuer());
	}

	/**
	 * Publish a credential revoke transaction to the ID chain.
	 *
	 * @param vc a VerifiableCredential object to be revoke
	 * @param signer the credential controller or issuer's DIDDocument
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for DIDStore
	 * @param adapter a DIDTransactionAdapter instance or null for default
	 * @throws DIDTransactionException if an error when publish the transaction
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected void revokeCredential(VerifiableCredential vc, DIDDocument signer,
			DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDTransactionException, DIDStoreException {
		CredentialRequest request = CredentialRequest.revoke(vc, signer,
				signKey, storepass);
		createTransaction(request, adapter);
		invalidCredentialCache(vc.getId(), null);
		invalidCredentialCache(vc.getId(), vc.getIssuer());
	}

	/**
	 * Publish a credential revoke transaction to the ID chain.
	 *
	 * @param vc a VerifiableCredential id to be revoke
	 * @param signer the credential controller or issuer's DIDDocument
	 * @param signKey the key to sign the transaction
	 * @param storepass the password for DIDStore
	 * @param adapter a DIDTransactionAdapter instance or null for default
	 * @throws DIDTransactionException if an error when publish the transaction
	 * @throws DIDStoreException if an error occurred when accessing the store
	 */
	protected void revokeCredential(DIDURL vc, DIDDocument signer,
			DIDURL signKey, String storepass, DIDTransactionAdapter adapter)
			throws DIDTransactionException, DIDStoreException {
		CredentialRequest request = CredentialRequest.revoke(vc, signer,
				signKey, storepass);
		createTransaction(request, adapter);
		invalidCredentialCache(vc, null);
		invalidCredentialCache(vc, signer.getSubject());
	}
}
