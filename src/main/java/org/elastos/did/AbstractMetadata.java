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

import java.text.ParseException;
import java.util.Date;
import java.util.Map;
import java.util.TreeMap;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;

/**
 * The class defines the base interface of Meta data.
 *
 */
public abstract class AbstractMetadata extends DIDObject<AbstractMetadata>
		implements Cloneable {
	private final static String ALIAS = "alias";

	protected final static String USER_EXTRA_PREFIX = "UX-";

	public TreeMap<String, String> props;
	private DIDStore store;

	/**
	 * Constructs the AbstractMetadata with the given value.
	 *
	 * @param store the DIDStore
	 */
	protected AbstractMetadata(DIDStore store) {
		this.store = store;
		this.props = new TreeMap<String, String>();
	}

	/**
	 * Constructs the AbstractMetadata with the given value.
	 *
	 * @param store the DIDStore
	 */
	protected AbstractMetadata() {
		this(null);
	}

	/**
	 * Set store for Abstract Metadata.
	 * @param store the DIDStore
	 */
	protected void attachStore(DIDStore store) {
		this.store = store;
	}

	protected void detachStore() {
		this.store = null;
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

	@JsonAnyGetter
	protected Map<String, String> getProperties() {
		return props;
	}

	@JsonAnySetter
	protected void put(String name, String value) {
		props.put(name, value);
		save();
	}

	protected String get(String name) {
		return props.get(name);
	}

	protected void put(String name, boolean value) {
		put(name, String.valueOf(value));
	}

	protected boolean getBoolean(String name) {
		return Boolean.valueOf(get(name));
	}

	protected void put(String name, int value) {
		put(name, String.valueOf(value));
	}

	protected int getInteger(String name) {
		return Integer.valueOf(get(name));
	}

	protected void put(String name, Date value) {
		put(name, dateFormat.format(value));
	}

	protected Date getDate(String name) throws ParseException {
		return dateFormat.parse(get(name));
	}

	protected String remove(String name) {
		String value = props.remove(name);
		save();
		return value;
	}

	public boolean isEmpty() {
		return props.isEmpty();
	}

	/**
	 * Set alias.
	 *
	 * @param alias alias string
	 */
	public void setAlias(String alias) {
		put(ALIAS, alias);
	}

	/**
	 * Get alias.
	 *
	 * @return alias string
	 */
	public String getAlias() {
		return get(ALIAS);
	}

	/**
	 * Set Extra element.
	 *
	 * @param key the key string
	 * @param value the value string
	 */
	public void setExtra(String key, String value) {
		checkArgument(key != null && !key.isEmpty(), "Invalid key");

		put(USER_EXTRA_PREFIX + key, value);
	}

	/**
	 * Get Extra element.
	 *
	 * @param key the key string
	 * @return the value string
	 */
	public String getExtra(String key) {
		checkArgument(key != null && !key.isEmpty(), "Invalid key");

		return get(USER_EXTRA_PREFIX + key);
	}

	public void setExtra(String key, Boolean value) {
		checkArgument(key != null && !key.isEmpty(), "Invalid key");

		put(USER_EXTRA_PREFIX + key, value);
	}

	public boolean getExtraBoolean(String key) {
		checkArgument(key != null && !key.isEmpty(), "Invalid key");

		return getBoolean(USER_EXTRA_PREFIX + key);
	}

	public void setExtra(String key, Integer value) {
		checkArgument(key != null && !key.isEmpty(), "Invalid key");

		put(USER_EXTRA_PREFIX + key, value);
	}

	public int getExtraInteger(String key) {
		checkArgument(key != null && !key.isEmpty(), "Invalid key");

		return getInteger(USER_EXTRA_PREFIX + key);
	}

	public void setExtra(String key, Date value) {
		checkArgument(key != null && !key.isEmpty(), "Invalid key");

		put(USER_EXTRA_PREFIX + key, value);
	}

	public Date getExtraDate(String key) throws ParseException {
		checkArgument(key != null && !key.isEmpty(), "Invalid key");

		return getDate(USER_EXTRA_PREFIX + key);
	}

	public String removeExtra(String key) {
		checkArgument(key != null && !key.isEmpty(), "Invalid key");

		return remove(USER_EXTRA_PREFIX + key);
	}

	/**
	 * Merge two metadata.
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
	@SuppressWarnings("unchecked")
	protected Object clone() throws CloneNotSupportedException {
		AbstractMetadata result = (AbstractMetadata)super.clone();
        result.store = store;
        result.props = (TreeMap<String, String>) props.clone();

        return result;
    }

	protected abstract void save();
}
