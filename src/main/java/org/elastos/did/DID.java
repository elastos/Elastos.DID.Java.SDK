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

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import org.elastos.did.exception.DIDBackendException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.MalformedDIDException;
import org.elastos.did.metadata.DIDMetadataImpl;
import org.elastos.did.parser.DIDURLBaseListener;
import org.elastos.did.parser.DIDURLParser;
import org.elastos.did.parser.ParserHelper;

/**
 * DID is a globally unique identifier that does not require
 * a centralized registration authority.
 */
public class DID implements Comparable<DID> {
	/**
	 * The default DID method filed
	 */
	public final static String METHOD = "elastos";

	private String method;
	private String methodSpecificId;

	private DIDMetadataImpl metadata;

	/**
	 * Get DID object.
	 */
	protected DID() {
	}

	/**
	 * Get DID object.
	 *
	 * @param method the method string. eg: "elastos:did:"
	 * @param methodSpecificId the method specific id string. eg: "i*******"
	 */
	protected DID(String method, String methodSpecificId) {
		this.method = method;
		this.methodSpecificId = methodSpecificId;
	}

	/**
	 * Get DID object.
	 *
	 * @param did the did string. eg: "elastos:did:i*******"
	 * @throws MalformedDIDException if the given did string has wrong format.
	 */
	public DID(String did) throws MalformedDIDException {
		if (did == null || did.isEmpty())
			throw new IllegalArgumentException();

		try {
			ParserHelper.parse(did, true, new Listener());
		} catch(IllegalArgumentException e) {
			throw new MalformedDIDException(e.getMessage());
		}
	}

	/**
	 * Get the did method string.
	 *
	 * @return the did method string
	 */
	public String getMethod() {
		return method;
	}

	/**
	 * Set the did method string.
	 *
	 * @param method the did method string
	 */
	protected void setMethod(String method) {
		this.method = method;
	}

	/**
	 * Get the did method specific id string.
	 *
	 * @return the did method specific id string
	 */
	public String getMethodSpecificId() {
		return methodSpecificId;
	}

	/**
	 * Set the did method specific id string.
	 *
	 * @param methodSpecificId the did method specific id string
	 */
	protected void setMethodSpecificId(String methodSpecificId) {
		this.methodSpecificId = methodSpecificId;
	}

	/**
	 * Set the metadata implement object for DID.
	 *
	 * @param metadata the metadata implement object
	 */
	protected void setMetadata(DIDMetadataImpl metadata) {
		this.metadata = metadata;
	}

	/**
	 * Get DIDMetadata object from DID.
	 *
	 * @return the DIDMetadata object
	 */
	public DIDMetadata getMetadata() {
		if (metadata == null)
			metadata = new DIDMetadataImpl();

		return metadata;
	}

	/**
	 * Store the DIDMetadata content of DID.
	 *
	 * @throws DIDStoreException throw this exception if storing DIDMetadata content failed.
	 */
	public void saveMetadata() throws DIDStoreException {
		if (metadata != null && metadata.attachedStore())
			metadata.getStore().storeDidMetadata(this, metadata);
	}

	/**
	 * Get the DID is deactivated or not.
	 *
	 * @return the DID deactivated status
	 */
	public boolean isDeactivated() {
		return getMetadata().isDeactivated();
	}

	/**
	 * Resolve DID content(DIDDocument).
	 *
	 * @param force force = true, DID content must be from chain.
	 *              force = false, DID content could be from chain or local cache.
	 * @return the DIDDocument object
	 * @throws DIDResolveException throw this exception if resolving did failed.
	 */
	public DIDDocument resolve(boolean force)
			throws DIDResolveException {
		DIDDocument doc = DIDBackend.resolve(this, force);
		if (doc != null)
			setMetadata(doc.getMetadataImpl());

		return doc;
	}

	/**
	 * Resolve DID content(DIDDocument) without force method.
	 *
	 * @return the DIDDocument object
	 * @throws DIDResolveException throw this exception if resolving did failed.
	 */
	public DIDDocument resolve()
			throws DIDResolveException {
		return resolve(false);
	}

	/**
	 * Resolve DID Document in asynchronous model.
	 *
	 * @param force force = true, DID content must be from chain.
	 *              force = false, DID content could be from chain or local cache.
	 * @return the new CompletableStage, the result is the DIDDocument interface for
	 *             resolved DIDDocument if success; null otherwise.
	 */
	public CompletableFuture<DIDDocument> resolveAsync(boolean force) {
		CompletableFuture<DIDDocument> future = CompletableFuture.supplyAsync(() -> {
			try {
				return resolve(force);
			} catch (DIDBackendException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Resolve DID Document without force method in asynchronous model.
	 *
	 * @return the new CompletableStage, the result is the DIDDocument interface for
	 *             resolved DIDDocument if success; null otherwise.
	 */
	public CompletableFuture<DIDDocument> resolveAsync() {
		return resolveAsync(false);
	}

	/**
	 * Resolve all DID transactions.
	 *
	 * @return the DIDHistory object
	 * @throws DIDResolveException throw this exception if resolving all did transactions failed.
	 */
	public DIDHistory resolveHistory() throws DIDResolveException {
		return DIDBackend.resolveHistory(this);
	}

	/**
	 * Resolve all DID transactions in asynchronous model.
	 *
	 * @return the new CompletableStage, the result is the DIDHistory interface for
	 *             resolved transactions if success; null otherwise.
	 */
	public CompletableFuture<DIDHistory> resolveHistoryAsync() {
		CompletableFuture<DIDHistory> future = CompletableFuture.supplyAsync(() -> {
			try {
				return resolveHistory();
			} catch (DIDResolveException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder(64);
		builder.append("did:")
			.append(method)
			.append(":")
			.append(methodSpecificId);

		return builder.toString();
	}

	@Override
	public int hashCode() {
		return METHOD.hashCode() + methodSpecificId.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this)
			return true;

		if (obj instanceof DID) {
			DID did = (DID)obj;
			boolean eq = method.equals(did.method);
			return eq ? methodSpecificId.equals(did.methodSpecificId) : eq;
		}

		if (obj instanceof String) {
			String did = (String)obj;
			return toString().equals(did);
		}

		return false;
	}


	@Override
	public int compareTo(DID did) {
		if (did == null)
			throw new IllegalArgumentException();

		int rc = method.compareTo(did.method);
		return rc == 0 ? methodSpecificId.compareTo(did.methodSpecificId) : rc;
	}

	class Listener extends DIDURLBaseListener {
		@Override
		public void exitMethod(DIDURLParser.MethodContext ctx) {
			String method = ctx.getText();
			if (!method.equals(DID.METHOD))
				throw new IllegalArgumentException("Unknown method: " + method);

			setMethod(DID.METHOD);
		}

		@Override
		public void exitMethodSpecificString(
				DIDURLParser.MethodSpecificStringContext ctx) {
			setMethodSpecificId(ctx.getText());
		}
	}
}
