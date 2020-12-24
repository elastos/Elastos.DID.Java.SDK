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

import java.io.File;
import java.io.IOException;
import java.util.Map;

import org.elastos.did.DID;
import org.elastos.did.DIDURL;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.util.LRUCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Preconditions;

/**
 * The class to store resolved did document in the temporary directory.
 */
public class ResolverCache {
	private static final int CACHE_INITIAL_CAPACITY = 16;
	private static final int CACHE_MAX_CAPACITY = 32;

	private File rootDir;
	private Map<Object, Object> cache = LRUCache.createInstance(
			CACHE_INITIAL_CAPACITY, CACHE_MAX_CAPACITY);

	private static final Logger log = LoggerFactory.getLogger(IDChainRequest.class);

	/**
	 * Create a resolver cache instance.
	 *
	 * @param rootDir the path of cache
	 */
	public ResolverCache(File rootDir) {
		Preconditions.checkArgument(rootDir != null && !rootDir.isFile(),
				"Invalid cache directory");
		this.rootDir = rootDir;

		if (!rootDir.exists())
			rootDir.mkdirs();
	}

	private File getCacheDir() {
		return rootDir;
	}

	private File getFile(DID did) {
		String filename = getCacheDir().getAbsolutePath() + File.separator
				+ did.getMethodSpecificId();
		return new File(filename);
	}

	private File getFile(DIDURL id) {
		String filename = getCacheDir().getAbsolutePath() + File.separator
				+ id.getDid().getMethodSpecificId() + "_" + id.getFragment();
		return new File(filename);
	}

	/**
	 * Reset the cache.
	 */
	public void reset() {
		cache.clear();

		File[] children = getCacheDir().listFiles();
		for (File child : children)
			child.delete();
	}

	/**
	 * Store the resolved DIDBiography in cache.
	 *
	 * @param rr the DIDBiography content
	 * @throws IOException write the resolve result to output failed.
	 */
	public void store(DIDBiography bio) throws IOException {
		try {
			bio.serialize(getFile(bio.getDid()));
			cache.put(bio.getDid(), bio);
		} catch (DIDSyntaxException ignore) {
			log.error("INTERNAL - Serialize DIDBiography", ignore);
		}
	}

	/**
	 * Store the resolved CredentialBiography in cache.
	 *
	 * @param rr the DIDBiography content
	 * @throws IOException write the resolve result to output failed.
	 */
	public void store(CredentialBiography bio) throws IOException {
		try {
			bio.serialize(getFile(bio.getId()));
			cache.put(bio.getId(), bio);
		} catch (DIDSyntaxException ignore) {
			log.error("INTERNAL - Serialize DIDBiography", ignore);
		}
	}

	/**
	 * Load the specified DID content from cache.
	 *
	 * @param did the specified DID
	 * @param ttl the time for cache
	 * @return the DIDBiography object
	 * @throws DIDResolveException resolve did failed.
	 */
	public DIDBiography load(DID did, long ttl)
			throws DIDResolveException {
		File file = getFile(did);

		if (!file.exists())
			return null;

		if (System.currentTimeMillis() > (file.lastModified() + ttl))
			return null;

		if (cache.containsKey(did))
			return (DIDBiography)cache.get(did);

		try {
			DIDBiography bio = DIDBiography.parse(file, DIDBiography.class);
			cache.put(bio.getDid(), bio);
			return bio;
		} catch (IOException | DIDSyntaxException e) {
			throw new DIDResolveException(e);
		}
	}

	/**
	 * Load the specified credential content from cache.
	 *
	 * @param id the specified id for credential
	 * @param ttl the time for cache
	 * @return the CredentialBiography object
	 * @throws DIDResolveException resolve did failed.
	 */
	public CredentialBiography load(DIDURL id, long ttl)
			throws DIDResolveException {
		File file = getFile(id);

		if (!file.exists())
			return null;

		if (System.currentTimeMillis() > (file.lastModified() + ttl))
			return null;

		if (cache.containsKey(id))
			return (CredentialBiography)cache.get(id);

		try {
			CredentialBiography bio = CredentialBiography.parse(file, CredentialBiography.class);
			cache.put(bio.getId(), bio);
			return bio;
		} catch (IOException | DIDSyntaxException e) {
			throw new DIDResolveException(e);
		}
	}

	/**
	 * Clean the cache data for the specified DID.
	 *
	 * @param did the specified DID
	 */
	public void invalidate(DID did) {
		File file = getFile(did);
		file.delete();
		cache.remove(did);
	}
}
