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
 * The abstract super class for all metadata objects.
 */
public abstract class AbstractMetadata extends DIDEntity<AbstractMetadata>
		implements Cloneable {
	private final static String ALIAS = "alias";

	/**
	 * The naming prefix for user defined metadata properties.
	 */
	protected final static String USER_EXTRA_PREFIX = "UX-";

	private TreeMap<String, String> props;
	private DIDStore store;

	/**
	 * Constructs an AbstractMetadata and attach with a DID store.
	 *
	 * @param store a DIDStore object
	 */
	protected AbstractMetadata(DIDStore store) {
		this.store = store;
		this.props = new TreeMap<String, String>();
	}

	/**
	 * Constructs an AbstractMetadata.
	 */
	protected AbstractMetadata() {
		this(null);
	}

	/**
	 * Attach this metadata object with a DID store.
	 *
	 * @param store a DID store object
	 */
	protected void attachStore(DIDStore store) {
		checkArgument(store != null, "Invalid store");
		this.store = store;
	}

	/**
	 * Detach this metadata object from the DID store.
	 */
	protected void detachStore() {
		this.store = null;
	}

	/**
	 * Get DID store if the metadata is attached with a store.
	 *
	 * @return the DIDStore object or null if not attached with a store
	 */
	protected DIDStore getStore() {
		return store;
	}

	/**
	 * Indicate whether the metadata object is attach the store.
	 *
	 * @return true if attached with a store, otherwise false
	 */
	protected boolean attachedStore() {
		return store != null;
	}

	/**
	 * Get all metadata properties as a map object.
	 *
	 * @return a map that contains all properties
	 */
	@JsonAnyGetter
	protected Map<String, String> getProperties() {
		return props;
	}

	/**
	 * Set the specified property name with with the specified value in
	 * this metadata. If the metadata previously contained this property,
	 * the old value is replaced.
	 *
	 * @param name the property name to be set
	 * @param value value to be associated with the property name
	 */
	@JsonAnySetter
	protected void put(String name, String value) {
		props.put(name, value);
		save();
	}

	/**
	 * Returns the value of the specified property name,
	 * or {@code null} if this metadata not contains the property name.
	 *
	 * @param name the property name to be get
	 * @return the value of the specified property name, or
	 *         {@code null} if this metadata not contains the property name
	 */
	protected String get(String name) {
		return props.get(name);
	}

	/**
	 * Type safe put method. Set the specified property name with with
	 * the specified value in this metadata. If the metadata previously
	 * contained this property, the old value is replaced.
	 *
	 * @param name the property name to be set
	 * @param value value to be associated with the property name
	 */
	protected void put(String name, boolean value) {
		put(name, String.valueOf(value));
	}

	/**
	 * Type safe getter for boolean properties. Returns the boolean value
	 * of the specified property name, or false if this metadata not contains
	 * the property name.
	 *
	 * @param name the property name to be get
	 * @param defaultValue the default value to be use if the property not exists
	 * @return the boolean value of the specified property name, or
	 *         false if this metadata not contains the property name
	 */
	protected boolean getBoolean(String name, boolean defaultValue) {
		String strValue = get(name);
		return strValue != null ? Boolean.valueOf(strValue) : defaultValue;
	}

	/**
	 * Type safe put method. Set the specified property name with with
	 * the specified value in this metadata. If the metadata previously
	 * contained this property, the old value is replaced.
	 *
	 * @param name the property name to be set
	 * @param value value to be associated with the property name
	 */
	protected void put(String name, int value) {
		put(name, String.valueOf(value));
	}

	/**
	 * Type safe getter for integer properties. Returns the integer value
	 * of the specified property name, or 0 if this metadata not contains
	 * the property name.
	 *
	 * @param name the property name to be get
	 * @param defaultValue the default value to be use if the property not exists
	 * @return the integer value of the specified property name, or
	 *         0 if this metadata not contains the property name
	 */
	protected int getInteger(String name, int defaultValue) {
		String strValue = get(name);
		int value = defaultValue;

		if (strValue != null) {
			try {
				value = Integer.valueOf(strValue);
			} catch (NumberFormatException ignore) {
			}
		}

		return value;
	}

	/**
	 * Type safe put method. Set the specified property name with with
	 * the specified value in this metadata. If the metadata previously
	 * contained this property, the old value is replaced.
	 *
	 * @param name the property name to be set
	 * @param value value to be associated with the property name
	 */
	protected void put(String name, Date value) {
		put(name, dateFormat.format(value));
	}

	/**
	 * Type safe getter for datetime properties. Returns the datatime value
	 * of the specified property name, or {@code null}  if this metadata not
	 * contains the property name.
	 *
	 * @param name the property name to be get
	 * @param defaultValue the default value to be use if the property not exists
	 * @return the Date value of the specified property name, or
	 *         null if this metadata not contains the property name
	 */
	protected Date getDate(String name, Date defaultValue) {
		String strValue = get(name);
		Date value = defaultValue;

		if (strValue != null) {
			try {
				value = dateFormat.parse(strValue);
			} catch (ParseException ignore) {
			}
		}

		return value;
	}

	/**
	 * Removes the specified property name from this metadata object if present.
	 *
	 * @param name the property name to be remove
	 * @return the previous value associated with {@code name}, or
	 *         {@code null} if there was no mapping for {@code name}.
	 */
	protected String remove(String name) {
		String value = props.remove(name);
		save();
		return value;
	}

	/**
	 * Returns {@code true} if this metadata contains no properties.
	 *
	 * @return {@code true} if this metadata contains no properties
	 */
	public boolean isEmpty() {
		return props.isEmpty();
	}

	/**
	 * Set the alias property.
	 *
	 * @param alias a new alias
	 */
	public void setAlias(String alias) {
		put(ALIAS, alias);
	}

	/**
	 * Get the alias property.
	 *
	 * @return alias current alias or null if not set before
	 */
	public String getAlias() {
		return get(ALIAS);
	}

	/**
	 * Set a user defined property name with with the specified value in
	 * this metadata. If the metadata previously contained this property,
	 * the old value is replaced.
	 *
	 * @param name the user defined property name to be set
	 * @param value value to be associated with the property name
	 */
	public void setExtra(String name, String value) {
		checkArgument(name != null && !name.isEmpty(), "Invalid key");

		put(USER_EXTRA_PREFIX + name, value);
	}

	/**
	 * Returns the value of the user defined property name,
	 * or {@code null} if this metadata not contains the property name.
	 *
	 * @param name the user defined property name to be get
	 * @return the value of the specified property name, or
	 *         {@code null} if this metadata not contains the property name
	 */
	public String getExtra(String name) {
		checkArgument(name != null && !name.isEmpty(), "Invalid name");

		return get(USER_EXTRA_PREFIX + name);
	}

	/**
	 * Type safe setter for user defined properties. Set the specified property
	 * name with the specified value in this metadata. If the metadata
	 * previously contained this property, the old value is replaced.
	 *
	 * @param name the property name to be set
	 * @param value value to be associated with the property name
	 */
	public void setExtra(String name, Boolean value) {
		checkArgument(name != null && !name.isEmpty(), "Invalid name");

		put(USER_EXTRA_PREFIX + name, value);
	}

	/**
	 * Type safe getter for boolean user defined properties. Returns the
	 * boolean value of the specified property name, or false if this metadata
	 * not contains the property name.
	 *
	 * @param name the property name to be get
	 * @param defaultValue the default value to be use if the property not exists
	 * @return the boolean value of the specified property name, or
	 *         false if this metadata not contains the property name
	 */
	public boolean getExtraBoolean(String name, boolean defaultValue) {
		checkArgument(name != null && !name.isEmpty(), "Invalid name");

		return getBoolean(USER_EXTRA_PREFIX + name, defaultValue);
	}

	/**
	 * Type safe setter for user defined properties. Set the specified property
	 * name with the specified value in this metadata. If the metadata
	 * previously contained this property, the old value is replaced.
	 *
	 * @param name the property name to be set
	 * @param value value to be associated with the property name
	 */
	public void setExtra(String name, Integer value) {
		checkArgument(name != null && !name.isEmpty(), "Invalid name");

		put(USER_EXTRA_PREFIX + name, value);
	}

	/**
	 * Type safe getter for integer user defined properties. Returns the
	 * integer value of the specified property name, or false if this metadata
	 * not contains the property name.
	 *
	 * @param name the property name to be get
	 * @param defaultValue the default value to be use if the property not exists
	 * @return the integer value of the specified property name, or
	 *         0 if this metadata not contains the property name
	 */
	public int getExtraInteger(String name, int defaultValue) {
		checkArgument(name != null && !name.isEmpty(), "Invalid name");

		return getInteger(USER_EXTRA_PREFIX + name, defaultValue);
	}

	/**
	 * Type safe setter for user defined properties. Set the specified property
	 * name with the specified value in this metadata. If the metadata
	 * previously contained this property, the old value is replaced.
	 *
	 * @param name the property name to be set
	 * @param value value to be associated with the property name
	 */
	public void setExtra(String name, Date value) {
		checkArgument(name != null && !name.isEmpty(), "Invalid name");

		put(USER_EXTRA_PREFIX + name, value);
	}

	/**
	 * Type safe getter for date time user defined properties. Returns the
	 * date time value of the specified property name, or false if this metadata
	 * not contains the property name.
	 *
	 * @param name the property name to be get
	 * @param defaultValue the default value to be use if the property not exists
	 * @return the Date value of the specified property name, or
	 *         {@code null} if this metadata not contains the property name
	 */
	public Date getExtraDate(String name, Date defaultValue) {
		checkArgument(name != null && !name.isEmpty(), "Invalid name");

		return getDate(USER_EXTRA_PREFIX + name, defaultValue);
	}

	/**
	 * Removes the specified user defined property name from this metadata
	 * object if present.
	 *
	 * @param name the user defined property name to be remove
	 * @return the previous value associated with {@code name}, or
	 *         {@code null} if there was no mapping for {@code name}.
	 */
	public String removeExtra(String name) {
		checkArgument(name != null && !name.isEmpty(), "Invalid name");

		return remove(USER_EXTRA_PREFIX + name);
	}

	/**
	 * Merge another metadata object into this metadata object.
	 *
	 * @param metadata the metadata to be merge
	 */
	protected void merge(AbstractMetadata metadata) {
		if (metadata == this || metadata == null)
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
	 * Returns a shallow copy of this instance: the property names and values
	 * themselves are not cloned.
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

	/**
	 * Abstract method to save the modified metadata to the attached store if
	 * this metadata attached with a store.
	 *
	 * If the child metadata class provide the save implementation, the metadata
	 * object will auto save after any modifications.
	 */
	protected abstract void save();
}
