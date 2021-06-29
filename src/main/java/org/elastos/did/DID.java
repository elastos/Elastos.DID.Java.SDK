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
import static com.google.common.base.Preconditions.checkNotNull;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import org.elastos.did.backend.DIDBiography;
import org.elastos.did.exception.DIDBackendException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.MalformedDIDException;
import org.elastos.did.parser.DIDURLBaseListener;
import org.elastos.did.parser.DIDURLParser;
import org.elastos.did.parser.ParserHelper;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

/**
 * DID is a globally unique identifier that does not require
 * a centralized registration authority.
 *
 * <p>
 * The generic DID scheme is a URI scheme conformant with
 * <a href="https://tools.ietf.org/html/rfc3986">RFC3986</a>
 * </p>
 */
@JsonSerialize(using = DID.Serializer.class)
@JsonDeserialize(using = DID.Deserializer.class)
public class DID implements Comparable<DID> {
	/**
	 * The default method name for Elastos DID method.
	 */
	public final static String METHOD = "elastos";

	private String method;
	private String methodSpecificId;

	private DIDMetadata metadata;

	/**
	 * Create a DID identifier with given method name and method specific id.
	 *
	 * @param method a method name. e.g. "elastos"
	 * @param methodSpecificId the method specific id string
	 */
	protected DID(String method, String methodSpecificId) {
		checkArgument(method != null && !method.isEmpty(), "Invalid method");
		checkArgument(methodSpecificId != null && !methodSpecificId.isEmpty(),
				"Invalid methodSpecificId");

		this.method = method;
		this.methodSpecificId = methodSpecificId;
	}

	/**
	 * Create a DID object from the given string. The method will parse the
	 * DID method and the method specific id from the string.
	 *
	 * @param did an identifier string.
	 * 			  e.g. "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN"
	 * @throws MalformedDIDException if the given identifier not compliant
	 * 				with the DID method specification
	 */
	public DID(String did) throws MalformedDIDException {
		checkArgument(did != null && !did.isEmpty(), "Invalid DID string");

		try {
			ParserHelper.parse(did, true, new Listener());
		} catch(IllegalArgumentException e) {
			throw new MalformedDIDException(did, e);
		}
	}

	/**
	 * Create a DID object from the given string. The method will parse the
	 * DID method and the method specific id from the string if the string is
	 * not empty. Otherwise will return null.
	 *
	 * @param did an identifier string.
	 * 			  e.g. "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN"
	 * @return the DID object if the did is not empty, otherwise null
	 * @throws MalformedDIDException if the given identifier not compliant
	 * 				with the DID method specification
	 */
	public static DID valueOf(String did) throws MalformedDIDException {
		return (did == null || did.isEmpty()) ? null : new DID(did);
	}

	/**
	 * Get the did method name.
	 *
	 * @return the did method name
	 */
	public String getMethod() {
		return method;
	}

	/**
	 * Get the method specific id string.
	 *
	 * @return the did method specific id string
	 */
	public String getMethodSpecificId() {
		return methodSpecificId;
	}

	/**
	 * Set the metadata that related with this DID.
	 *
	 * @param metadata a metadata object
	 */
	protected void setMetadata(DIDMetadata metadata) {
		this.metadata = metadata;
	}

	/**
	 * Get the metadata object that associated with this DID.
	 *
	 * @return the metadata object
	 */
	public synchronized DIDMetadata getMetadata() {
		if (metadata == null) {
			try {
				DIDDocument resolved = resolve();
				metadata = resolved != null ? resolved.getMetadata() : new DIDMetadata(this);
			} catch (DIDResolveException e) {
				metadata = new DIDMetadata(this);
			}
		}

		return metadata;
	}

	/**
	 * Check the DID is deactivated or not.
	 *
	 * @return the DID deactivated status
	 */
	public boolean isDeactivated() {
		return getMetadata().isDeactivated();
	}

	/**
	 * Resolve the DID document.
	 *
	 * @param force if true then ignore the local cache and resolve the DID
	 * 				from the ID chain directly; otherwise will try to load
	 * 				the document from the local cache, if the local cache
	 * 				not contains this DID, then resolve it from the ID chain
	 *
	 * @return the DIDDocument object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
	public DIDDocument resolve(boolean force)
			throws DIDResolveException {
		DIDDocument doc = DIDBackend.getInstance().resolveDid(this, force);
		if (doc != null)
			setMetadata(doc.getMetadata());

		return doc;
	}

	/**
	 * Resolve the DID document.
	 *
	 * <p>
	 * By default, this method will try to load the document from the local
	 * cache, if the local cache not contains this DID, then try to resolve
	 * it from the ID chain.
	 * </p>
	 *
	 * @return the DIDDocument object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
	public DIDDocument resolve()
			throws DIDResolveException {
		return resolve(false);
	}

	/**
	 * Resolve DID Document in asynchronous mode.
	 *
	 * @param force if true then ignore the local cache and resolve the DID
	 * 				from the ID chain directly; otherwise will try to load
	 * 				the document from the local cache, if the local cache
	 * 				not contains this DID, then resolve it from the ID chain
	 * @return a new CompletableStage, the result is the resolved DIDDocument
	 * 			object if success; null otherwise
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
	 * Resolve DID Document in asynchronous mode.
	 *
	 * By default, this method will try to load the document from the local
	 * cache, if the local cache not contains this DID, then try to resolve
	 * it from the ID chain
	 *
	 * @return a new CompletableStage, the result is the resolved DIDDocument
	 * 			object if success; null otherwise
	 */
	public CompletableFuture<DIDDocument> resolveAsync() {
		return resolveAsync(false);
	}

	/**
	 * Resolve all DID transactions.
	 *
	 * @return the DIDBiography object
	 * @throws DIDResolveException if an error occurred when resolving DID
	 */
	public DIDBiography resolveBiography() throws DIDResolveException {
		return DIDBackend.getInstance().resolveDidBiography(this);
	}

	/**
	 * Resolve all DID transactions in asynchronous mode.
	 *
	 * @return a new CompletableStage, the result is the resolved DIDBiography
	 * 			object if success; null otherwise
	 */
	public CompletableFuture<DIDBiography> resolveBiographyAsync() {
		CompletableFuture<DIDBiography> future = CompletableFuture.supplyAsync(() -> {
			try {
				return resolveBiography();
			} catch (DIDResolveException e) {
				throw new CompletionException(e);
			}
		});

		return future;
	}

	/**
	 * Return the string representation of this DID object.
	 *
	 * @return a string representation of this DID object
	 */
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder(64);
		builder.append("did:")
			.append(method)
			.append(":")
			.append(methodSpecificId);

		return builder.toString();
	}

	/**
	 * Returns a hash code for this DID object.
	 *
	 * @return a hash code value for this object
	 */
	@Override
	public int hashCode() {
		return METHOD.hashCode() + methodSpecificId.hashCode();
	}

	/**
	 * Compares this DID to the specified object. The result is true if and
	 * only if the argument is not null and is a DID object that represents
	 * the same identifier.
	 *
	 * @param obj the object to compare this DID against
	 * @return true if the given object represents a DID equivalent to this
	 * 			object, false otherwise
	 */
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

	/**
	 * Compares this DID with the specified DID.
	 *
	 * @param did DID to which this DID is to be compared
	 * @return -1, 0 or 1 as this DID is less than, equal to,
	 * 		   or greater than did
	 */
	@Override
	public int compareTo(DID did) {
		checkNotNull(did, "did is null");

		int rc = method.compareTo(did.method);
		return rc == 0 ? methodSpecificId.compareTo(did.methodSpecificId) : rc;
	}

	static class Serializer extends StdSerializer<DID> {
		private static final long serialVersionUID = -5048323762128760963L;

		public Serializer() {
			this(null);
		}

		public Serializer(Class<DID> t) {
			super(t);
		}

		@Override
		public void serialize(DID did, JsonGenerator gen,
				SerializerProvider provider) throws IOException {
			gen.writeString(did.toString());
		}
	}

	static class Deserializer extends StdDeserializer<DID> {
		private static final long serialVersionUID = -306953602840919050L;

		public Deserializer() {
			this(null);
		}

		public Deserializer(Class<?> vc) {
			super(vc);
		}

		@Override
		public DID deserialize(JsonParser p, DeserializationContext ctxt)
				throws IOException, JsonProcessingException {
			JsonToken token = p.getCurrentToken();
			if (!token.equals(JsonToken.VALUE_STRING))
				throw ctxt.weirdStringException(p.getText(), DID.class, "Invalid DIDURL");

			String did = p.getText().trim();

			try {
				return new DID(did);
			} catch (MalformedDIDException e) {
				throw ctxt.weirdStringException(did, DID.class, "Invalid DID");
			}
		}

	}

	class Listener extends DIDURLBaseListener {
		@Override
		public void exitMethod(DIDURLParser.MethodContext ctx) {
			String method = ctx.getText();
			if (!method.equals(DID.METHOD))
				throw new IllegalArgumentException("Unknown method: " + method);

			DID.this.method = method;
		}

		@Override
		public void exitMethodSpecificString(
				DIDURLParser.MethodSpecificStringContext ctx) {
			DID.this.methodSpecificId = ctx.getText();
		}
	}
}
