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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Random;

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
import org.elastos.did.backend.ResolverCache;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.DIDTransactionException;
import org.elastos.did.exception.InvalidKeyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The class is to provide the backend for resolving DID.
 */
public class DIDBackend {
	private static final long DEFAULT_TTL = 24 * 60 * 60 * 1000;

	private static Random random = new Random();

	private DIDAdapter adapter;
	private ResolveHandle resolveHandle;

	private ResolverCache cache;
	private long ttl = DEFAULT_TTL; // milliseconds

	private static final Logger log = LoggerFactory.getLogger(DIDBackend.class);

	// TODO: add application context support
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
     * Set DIDAdapter for DIDBackend.
     *
     * @param adapter the DIDAdapter object
     */
	private DIDBackend(DIDAdapter adapter, File cacheDir) {
		checkArgument(adapter != null, "Invalid adapter");
		checkArgument(cacheDir != null && !cacheDir.isFile(), "Invalid cache directory");

		this.adapter = adapter;
		this.cache = new ResolverCache(cacheDir);
	}

    /**
	 * Initialize DIDBackend to resolve by url string and cache path stored the document in ttl time.
	 * Recommendation for cache dir:
	 * - Laptop/standard Java
	 *   System.getProperty("user.home") + "/.cache.did.elastos"
	 * - Android Java
	 *   Context.getFilesDir() + "/.cache.did.elastos"
     *
     * @param adapter the DIDAdapter object
     * @param cacheDir the cache path name
     */
	public static void initialize(DIDAdapter adapter, File cacheDir) {
		instance = new DIDBackend(adapter, cacheDir);
	}

    /**
	 * Initialize DIDBackend to resolve by url string and cache path stored the document in ttl time.
	 * Recommendation for cache dir:
	 * - Laptop/standard Java
	 *   System.getProperty("user.home") + "/.cache.did.elastos"
	 * - Android Java
	 *   Context.getFilesDir() + "/.cache.did.elastos"
     *
     * @param adapter the DIDAdapter object
     * @param cacheDir the cache path name
     */
	public static void initialize(DIDAdapter adapter, String cacheDir) {
		checkArgument(cacheDir != null && !cacheDir.isEmpty(), "Invalid cache directory");

		initialize(adapter, new File(cacheDir));
	}

	/**
	 * Get DIDBackend instance according to specified DIDAdapter object.
	 *
	 * @return the DIDBackend instance
	 */
	public static DIDBackend getInstance() {
		return instance;
	}

	/**
	 * Set the cache time to live in minutes.
	 *
	 * @param ttl the validate time to store content
	 */
	public void setTTL(long ttl) {
		ttl = ttl > 0 ? (ttl * 60 * 1000) : 0;
	}

	/**
	 * Get the cache time to live in minutes.
	 *
	 * @return the validate time to live
	 */
	public long getTTL() {
		return ttl != 0 ? (ttl / 60 / 1000) : 0;
	}

	private String generateRequestId() {
		StringBuffer sb = new StringBuffer();

		while(sb.length() < 16)
			sb.append(Integer.toHexString(random.nextInt()));

		return sb.toString();
	}

	public void resetCache() {
		cache.reset();
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

	private InputStream resolve(ResolveRequest<?, ?> request)
			throws DIDResolveException {
		try {
			String requestJson = request.serialize(true);
			return getAdapter().resolve(requestJson);
		} catch (DIDSyntaxException e) {
			log.error("INTERNAL - Serialize resolve request", e);
			throw new DIDResolveException("Can not serialize the request", e);
		}
	}

	private DIDBiography resolveDidFromBackend(DID did, boolean all)
			throws DIDResolveException {
		String requestId = generateRequestId();
		DIDResolveRequest request = new DIDResolveRequest(requestId);
		request.setParameters(did, all);
		InputStream is = resolve(request);

		DIDResolveResponse response;
		try {
			response = DIDResolveResponse.parse(is, DIDResolveResponse.class);
		} catch (DIDSyntaxException | IOException e) {
			throw new DIDResolveException(e);
		} finally {
			try {
				is.close();
			} catch (IOException ignore) {
			}
		}

		if (response.getResponseId() == null || !response.getResponseId().equals(requestId))
			throw new DIDResolveException("Mismatched resolve result with request.");

		DIDBiography bio = response.getResult();
		if (bio == null) {
			throw new DIDResolveException("Resolve DID error("
					+ response.getErrorCode() + "): " + response.getErrorMessage());
		}

		if (bio.getStatus() != DIDBiography.Status.NOT_FOUND) {
			try {
				cache.store(bio);
			} catch (IOException e) {
				log.error("!!! Cache resolved result error !!!", e);
			}
		}

		return bio;
	}

    /**
     * Resolve all DID transactions.
     *
     * @param did the specified DID object
     * @return the DIDBiography object
     * @throws DIDResolveException throw this exception if resolving did transcations failed.
     */
	protected DIDBiography resolveDidBiography(DID did) throws DIDResolveException {
		log.info("Resolving {}...", did.toString());

		DIDBiography rr = resolveDidFromBackend(did, true);
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
		log.info("Resolving DID {}...", did.toString());

		if (resolveHandle != null) {
			DIDDocument doc = resolveHandle.resolve(did);
			if (doc != null)
				return doc;
		}

		DIDBiography bio = null;
		if (!force) {
			bio = cache.load(did, ttl);
			log.debug("Try load {} from resolver cache: {}.",
					did.toString(), bio == null ? "non" : "matched");
		}

		if (bio == null)
			bio = resolveDidFromBackend(did, false);

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
		DIDMetadata metadata = new DIDMetadata();
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

	protected CredentialBiography resolveCredentialBiography(DIDURL id, DID issuer)
			throws DIDResolveException {
		String requestId = generateRequestId();
		CredentialResolveRequest request = new CredentialResolveRequest(requestId);
		request.setParameters(id, issuer);
		InputStream is = resolve(request);

		CredentialResolveResponse response;
		try {
			response = CredentialResolveResponse.parse(is, CredentialResolveResponse.class);
		} catch (DIDSyntaxException | IOException e) {
			throw new DIDResolveException(e);
		} finally {
			try {
				is.close();
			} catch (IOException ignore) {
			}
		}

		if (response.getResponseId() == null || !response.getResponseId().equals(requestId))
			throw new DIDResolveException("Mismatched resolve result with request.");

		CredentialBiography bio = response.getResult();
		if (bio == null) {
			throw new DIDResolveException("Resolve credential error("
					+ response.getErrorCode() + "): " + response.getErrorMessage());
		}

		if (bio.getStatus() != CredentialBiography.Status.NOT_FOUND) {
			try {
				cache.store(bio);
			} catch (IOException e) {
				log.error("!!! Cache resolved result error !!!", e);
			}
		}

		return bio;

	}

	protected CredentialBiography resolveCredentialBiography(DIDURL id)
			throws DIDResolveException {
		return resolveCredentialBiography(id, null);
	}

	protected VerifiableCredential resolveCredential(DIDURL id, DID issuer, boolean force)
			throws DIDResolveException {
		log.info("Resolving credential {}...", id);

		CredentialBiography bio = null;
		if (!force) {
			bio = cache.load(id, ttl);
			log.debug("Try load {} from resolver cache: {}.",
					id.toString(), bio == null ? "non" : "matched");
		}

		if (bio == null)
			bio = resolveCredentialBiography(id, issuer);

		CredentialTransaction tx = null;
		switch (bio.getStatus()) {
		case VALID:
			tx = bio.getTransaction(0);
			break;

		case REVOKED:
			tx = bio.getTransaction(0);
			if (tx.getRequest().getOperation() != IDChainRequest.Operation.REVOKE)
				throw new DIDResolveException("Invalid credential biography, wrong status.");

			if (!tx.getRequest().isValid())
				throw new DIDResolveException("Invalid credential biography, transaction signature mismatch.");

			if (bio.getTransactionCount() == 1)
				return null;

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
		CredentialMetadata metadata = new CredentialMetadata();
		metadata.setPublished(tx.getTimestamp());
		if (bio.getStatus() == CredentialBiography.Status.REVOKED)
			metadata.setRevoked(true);
		vc.setMetadata(metadata);
		return vc;
	}

	protected VerifiableCredential resolveCredential(DIDURL id, boolean force)
			throws DIDResolveException {
		return resolveCredential(id, null, force);
	}

	protected VerifiableCredential resolveCredential(DIDURL id, DID issuer)
			throws DIDResolveException {
		return resolveCredential(id, issuer, false);
	}

	protected VerifiableCredential resolveCredential(DIDURL id)
			throws DIDResolveException {
		return resolveCredential(id, false);
	}

	protected boolean resolveCredentialRevocation(DIDURL id, DID signer)
		throws DIDResolveException {
		log.info("Resolving credential revocation {}...", id);

		CredentialBiography bio = resolveCredentialBiography(id, signer);
		return bio.getStatus() == CredentialBiography.Status.REVOKED;
	}

	protected List<DIDURL> listCredentials(DID did, int skip, int limit)
			throws DIDResolveException {
		log.info("List credentials for {}", did);

		String requestId = generateRequestId();
		CredentialListRequest request = new CredentialListRequest(requestId);
		request.setParameters(did, skip, limit);
		InputStream is = resolve(request);

		CredentialListResponse response;
		try {
			response = CredentialListResponse.parse(is, CredentialListResponse.class);
		} catch (DIDSyntaxException | IOException e) {
			throw new DIDResolveException(e);
		} finally {
			try {
				is.close();
			} catch (IOException ignore) {
			}
		}

		if (response.getResponseId() == null || !response.getResponseId().equals(requestId))
			throw new DIDResolveException("Mismatched resolve result with request.");

		CredentialList list = response.getResult();
		if (list == null || list.size() == 0)
			return null;

		return list.getCredentialIds();
	}

	private void createTransaction(IDChainRequest<?> request)
			throws DIDTransactionException {
		log.info("Create ID transaction...");

		try {
			String payload = request.serialize(true);
			log.trace("Transaction paload: '{}', memo: {}", payload, "");
			getAdapter().createIdTransaction(payload, null);
		} catch (DIDSyntaxException e) {
			log.error("INTERNAL - Serialize IDChainRequest failed", e);
			throw new DIDTransactionException("Serialize IDChainRequest failed", e);
		}

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
	protected void createDid(DIDDocument doc, DIDURL signKey, String storepass)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		DIDRequest request = DIDRequest.create(doc, signKey, storepass);
		createTransaction(request);
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
			DIDURL signKey, String storepass)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		DIDRequest request = DIDRequest.update(doc, previousTxid, signKey, storepass);
		createTransaction(request);
		cache.invalidate(doc.getSubject());
	}

	protected void transferDid(DIDDocument doc, TransferTicket ticket,
			DIDURL signKey, String storepass)
			throws DIDStoreException, InvalidKeyException, DIDTransactionException {
		DIDRequest request = DIDRequest.transfer(doc, ticket, signKey, storepass);
		createTransaction(request);
		cache.invalidate(doc.getSubject());
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
	protected void deactivateDid(DIDDocument doc, DIDURL signKey, String storepass)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		DIDRequest request = DIDRequest.deactivate(doc, signKey, storepass);
		createTransaction(request);
		cache.invalidate(doc.getSubject());
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
			DIDDocument signer, DIDURL signKey, String storepass)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		DIDRequest request = DIDRequest.deactivate(target,
				targetSignKey, signer, signKey, storepass);
		createTransaction(request);
		cache.invalidate(target.getSubject());
	}

	protected void declareCredential(VerifiableCredential vc, DIDDocument signer,
			DIDURL signKey, String storepass)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		CredentialRequest request = CredentialRequest.declare(vc, signer,
				signKey, storepass);
		createTransaction(request);
	}

	protected void revokeCredential(VerifiableCredential vc, DIDDocument signer,
			DIDURL signKey, String storepass)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		CredentialRequest request = CredentialRequest.revoke(vc, signer,
				signKey, storepass);
		createTransaction(request);
	}

	protected void revokeCredential(DIDURL vc, DIDDocument signer,
			DIDURL signKey, String storepass)
			throws DIDTransactionException, DIDStoreException, InvalidKeyException {
		CredentialRequest request = CredentialRequest.revoke(vc, signer,
				signKey, storepass);
		createTransaction(request);
	}
}
