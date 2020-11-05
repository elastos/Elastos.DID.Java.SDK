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

import java.util.Map;
import java.util.TreeMap;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * The class defines the base interface of Meta data.
 *
 */
public abstract class AbstractMetadata extends DIDObject<AbstractMetadata> {
	protected final static String RESERVED_PREFIX = "DX-";

	public TreeMap<String, Object> props;
	private DIDStore store;

	/**
	 * Constructs the AbstractMetadata with the given value.
	 *
	 * @param store the DIDStore
	 */
	protected AbstractMetadata(DIDStore store) {
		this.store = store;
		this.props = new TreeMap<String, Object>();
	}

	@JsonAnyGetter
	@JsonPropertyOrder(alphabetic = true)
	private Map<String, Object> getProperties() {
		return props;
	}

	@JsonAnySetter
	protected void put(String name, Object value) {
		props.put(name, value);
	}

	protected Object get(String name) {
		return props.get(name);
	}

	protected Object remove(String name) {
		return props.remove(name);
	}

	public boolean isEmpty() {
		return props.isEmpty();
	}

	/**
	 * Set store for Abstract Metadata.
	 * @param store the DIDStore
	 */
	protected void setStore(DIDStore store) {
		this.store = store;
	}

	/**
	 * Get store from Abstract Metadata.
	 *
	 * @return the DIDStore object
	 */
	protected DIDStore getStore() {
		return store;
	}

	/**
	 * Judge whether the Abstract Metadata attach the store or not.
	 *
	 * @return the returned value is true if there is store attached meta data;
	 *         the returned value is false if there is no store attached meta data.
	 */
	protected boolean attachedStore() {
		return store != null;
	}

	/**
	 * Set Extra element.
	 *
	 * @param key the key string
	 * @param value the value string
	 */
	public void setExtra(String key, String value) {
		if (key == null || key.isEmpty())
			throw new IllegalArgumentException();

		put(key, value);
	}

	/**
	 * Get Extra element.
	 *
	 * @param key the key string
	 * @return the value string
	 */
	public String getExtra(String key) {
		if (key == null || key.isEmpty())
			throw new IllegalArgumentException();

		return (String)get(key);
	}

	/**
	 * Merge two meta datas.
	 *
	 * @param metadata the metadata to be merged.
	 */
	protected void merge(AbstractMetadata metadata) {
		if (metadata == this)
			return;

		metadata.props.forEach((k, v) -> {
			if (props.containsKey(k)) {
				if (props.get(k) == null)
					props.remove(k);
			} else {
				if (v != null)
					props.put(k, v);
			}
		});
	}

    /**
     * Returns a shallow copy of this instance: the keys and values themselves
     * are not cloned.
     *
     * @return a shallow copy of this object
     */
	@Override
	protected Object clone() throws CloneNotSupportedException {
		AbstractMetadata result = (AbstractMetadata)super.clone();
        result.store = store;
        @SuppressWarnings("unchecked")
		TreeMap<String, Object> map = (TreeMap<String, Object>) props.clone();
		result.props = map;

        return result;
    }

}
