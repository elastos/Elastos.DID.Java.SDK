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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.elastos.did.DIDEntity.SerializeContext;
import org.elastos.did.VerifiableCredential.Proof;
import org.elastos.did.exception.MalformedDIDURLException;
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
 * Class DIDURL represents a Uniform Resource Locator, a pointer to
 * a specific DID resource. It can be used to retrieve things like
 * representations of DID subjects, verification methods, services,
 * specific parts of a DID document, or other resources.
 */
@JsonSerialize(using = DIDURL.Serializer.class)
@JsonDeserialize(using = DIDURL.Deserializer.class)
public class DIDURL implements Comparable<DIDURL> {
	private final static String SEPS = ":;/?#";

	private DID did;
	private Map<String, String> parameters;
	private String path;
	private Map<String, String> query;
	private String fragment;

	private AbstractMetadata metadata;

	/**
	 * Constructs a DIDURL object with the given DID base and a url string.
	 *
	 * @param baseRef a DID base of the DIDURL object, if the url is a relative DIDURL
	 * @param url a string representation of DIDURL
	 * @throws MalformedDIDURLException if the url in wrong syntax
	 */
	public DIDURL(DID baseRef, String url) throws MalformedDIDURLException {
		checkArgument(url != null && !url.isEmpty(), "Invalid url");

		// Compatible with v1, support fragment without leading '#'
		if (!url.startsWith("did:")) {
			boolean noSep = true;
			char[] chars = url.toCharArray();
			for (char ch : chars) {
				if (SEPS.indexOf(ch) >= 0) {
					noSep = false;
					break;
				}
			}

			if (noSep) // fragment only
				url = "#" + url;
		}

		try {
			ParserHelper.parse(url, false, new Listener());

			if (parameters == null || parameters.isEmpty())
				parameters = Collections.emptyMap();

			if (query == null || query.isEmpty())
				query = Collections.emptyMap();

		} catch (Exception e) {
			throw new MalformedDIDURLException(url, e);
		}

		if (this.did == null && baseRef != null)
			this.did = baseRef;
	}

	/**
	 * Constructs a DIDURL object.
	 *
	 * @param url a string representation of DIDURL
	 * @throws MalformedDIDURLException if the url in wrong syntax
	 */
	public DIDURL(String url) throws MalformedDIDURLException {
		this(null, url);
	}

	/**
	 * Constructs a DIDURL object with the given DID base and a DIDURL object.
	 *
	 * @param baseRef a DID base of the DIDURL object, if the url is a relative DIDURL
	 * @param url a DIDURL object
	 */
	public DIDURL(DID baseRef, DIDURL url) {
		checkArgument(url != null, "Invalid url");

		this.did = url.did == null ? baseRef : url.did;
		this.parameters = url.parameters;
		this.path = url.path;
		this.query = url.query;
		this.fragment = url.fragment;
		this.metadata = url.metadata;
	}

	/**
	 * Constructs a DIDURL object from DID object.
	 *
	 * @param did a DID base of the DIDURL object
	 */
	protected DIDURL(DID did) {
		this.did = did;
		this.parameters = Collections.emptyMap();
		this.query = Collections.emptyMap();
	}

	/**
	 * Deep-copy constructor.
	 *
	 * @param url a source DIDURL object
	 */
	private DIDURL(DIDURL url) {
		this.did = url.did;
		this.parameters = url.parameters.isEmpty() ? Collections.emptyMap() :
				new LinkedHashMap<String, String>(url.parameters);
		this.path = url.path;
		this.query = url.query.isEmpty() ? Collections.emptyMap() :
				new LinkedHashMap<String, String>(url.query);
		this.fragment = url.fragment;
	}

	/**
	 * Create a DIDURL object from the given string. The method will parse the
	 * DIDURL object from the string if the string is not empty. Otherwise
	 * will return null. If the parsed DIDURL object is relative, then use
	 * baseRef as it's base DID.
	 *
	 * @param baseRef a DID base of the DIDURL object, if the url is a relative DIDURL
	 * @param url a string representation of DIDURL
	 * @return a DIDURL object if url isn't null or empty; otherwise null
	 * @throws MalformedDIDURLException if the url in wrong syntax
	 */
	public static DIDURL valueOf(DID baseRef, String url) throws MalformedDIDURLException {
		return (url == null || url.isEmpty()) ? null : new DIDURL(baseRef, url);
	}

	/**
	 * Create a DIDURL object from the given string. The method will parse the
	 * DIDURL object from the string if the string is not empty. Otherwise
	 * will return null. If the parsed DIDURL object is relative, then use
	 * baseRef as it's base DID.
	 *
	 * @param baseRef a DID base of the DIDURL object, if the url is a relative DIDURL
	 * @param url a string representation of DIDURL
	 * @return a DIDURL object if url isn't null or empty; otherwise null
	 * @throws MalformedDIDURLException if the url in wrong syntax
	 */
	public static DIDURL valueOf(String baseRef, String url) throws MalformedDIDURLException {
		return (url == null || url.isEmpty()) ? null : new DIDURL(DID.valueOf(baseRef), url);
	}

	/**
	 * Create a DIDURL object from the given string. The method will parse the
	 * DIDURL object from the string if the string is not empty. Otherwise
	 * will return null.
	 *
	 * @param url a string representation of DIDURL
	 * @return a DIDURL object if url isn't null or empty; otherwise null
	 * @throws MalformedDIDURLException if the url in wrong syntax
	 */
	public static DIDURL valueOf(String url) throws MalformedDIDURLException {
		return (url == null || url.isEmpty()) ? null : new DIDURL(url);
	}

	/**
	 * Get the base DID of the DIDURL object.
	 *
	 * @return the DID object
	 */
	public DID getDid() {
		return did;
	}

	/**
	 * Set the base DID of the DIDURL object.
	 *
	 * @param did the DID Object, could be null
	 */
	protected void setDid(DID did) {
		this.did = did;
	}

	private String mapToString(Map<String, String> map, String sep) {
		boolean init = true;

		StringBuilder builder = new StringBuilder(512);
		for (Map.Entry<String, String> entry : map.entrySet()) {
			if (init)
				init = false;
			else
				builder.append(sep);

			builder.append(entry.getKey());
			if (entry.getValue() != null)
				builder.append("=").append(entry.getValue());
		}

		return builder.toString();
	}

	/**
	 * Get the decoded DID parameters component from this DIDURL.
	 *
	 * @return the decoded parameters string or null if the parameters
	 * 		   component is undefined
	 */
	public String getParametersString() {
		if (parameters.isEmpty())
			return null;

		return mapToString(parameters, ";");
	}

	/**
	 * Get DID parameters component as a map.
	 *
	 * @return a key/value map that contains all parameters or null
	 * 		   if the parameters component is undefined
	 */
	public Map<String, String> getParameters() {
		return Collections.unmodifiableMap(parameters);
	}

	/**
	 * Get the value of the given DID parameter.
	 *
	 * @param name the parameter name
	 * @return the value of parameter or null if the given parameter is undefined
	 */
	public String getParameter(String name) {
		checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");
		return parameters.get(name);
	}

	/**
	 * Check whether the given parameter exists in the DID parameters component.
	 *
	 * @param name the name of parameter
	 * @return true if the has a parameter with given name or false otherwise
	 */
	public boolean hasParameter(String name) {
		checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");
		return parameters.containsKey(name);
	}

	/**
	 * Get the decoded path component of this DIDURL.
	 *
	 * @return the decoded path component of this DIDURL, or null if
	 * 		   the path is undefined
	 */
	public String getPath() {
		return path;
	}

	/**
	 * Get the decoded query component of this DIDURL.
	 *
	 * @return the decoded query component of this DIDURL,
	 * 		   or null if the query is undefined
	 */
	public String getQueryString() {
		if (query.isEmpty())
			return null;

		return mapToString(query, "&");
	}

	/**
	 * Get the query component of this DIDURL as a map.
	 *
	 * @return the decoded query component of this DIDURL,
	 * 		   or null if the query is undefined
	 */
	public Map<String, String> getQuery() {
		return Collections.unmodifiableMap(query);
	}

	/**
	 * Get the value of the given query parameter.
	 *
	 * @param name the parameter name
	 * @return the value of parameter or null if the given parameter is undefined
	 */
	public String getQueryParameter(String name) {
		checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");
		return query.get(name);
	}

	/**
	 * Check whether the given parameter exists in the query component.
	 *
	 * @param name the name of parameter
	 * @return true if the has a parameter with given name or false otherwise
	 */
	public boolean hasQueryParameter(String name) {
		checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");
		return query.containsKey(name);
	}

	/**
	 * Get the decoded fragment component of this DIDURL.
	 *
	 * @return the fragment string
	 */
	public String getFragment() {
		return fragment;
	}

	/**
	 * Set the metadata that related with this DIDURL object.
	 *
	 * @param metadata a metadata object
	 */
	protected void setMetadata(AbstractMetadata metadata) {
		this.metadata = metadata;
	}

	/**
	 * Get the metadata object that associated with this DIDURL object.
	 *
	 * @return the metadata object
	 */
	public AbstractMetadata getMetadata() {
		return metadata;
	}

	/**
	 * Return the string representation of this DIDURL object. If the base DID
	 * isn't null, the result will be a relative representation.
	 *
	 * @param base a base DID reference object for relative DIDURL
	 * @return a relative string representation of this DIDURL object
	 */
	protected String toString(DID base) {
		StringBuilder builder = new StringBuilder(512);
		if (did != null && (base == null || !did.equals(base)))
			builder.append(did);

		if (parameters != null && !parameters.isEmpty())
			builder.append(";").append(getParametersString());

		if (path != null && !path.isEmpty())
			builder.append(path);

		if (query != null && !query.isEmpty())
			builder.append("?").append(getQueryString());

		if (fragment != null && !fragment.isEmpty())
			builder.append("#").append(getFragment());

		return builder.toString();
	}

	/**
	 * Return the string representation of this DIDURL object.
	 *
	 * @return a string representation of this DIDURL object
	 */
	@Override
	public String toString() {
		return toString(null);
	}

	/**
	 * Compares this DIDURL to the specified object. The result is true if and
	 * only if the argument is not null and is a DIDURL object that represents
	 * the same resource.
	 *
	 * @param obj the object to compare this DID against
	 * @return true if the given object represents a DIDURL equivalent to this
	 * 			resource, false otherwise
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == this)
			return true;

		if (obj instanceof DIDURL) {
			DIDURL id = (DIDURL)obj;
			return toString().equals(id.toString());
		}

		if (obj instanceof String) {
			String url = (String)obj;
			return toString().equals(url);
		}

		return false;
	}

	/**
	 * Compares this DIDURL with the specified DIDURL.
	 *
	 * @param id DIDURL to which this DIDURL is to be compared
	 * @return -1, 0 or 1 as this DIDURL is less than, equal to,
	 * 		   or greater than id
	 */
	@Override
	public int compareTo(DIDURL id) {
		checkNotNull(id, "id is null");

		return toString().compareTo(id.toString());
	}

	private int mapHashCode(Map<String, String> map) {
		int hash = 0;

		for (Map.Entry<String, String> entry : map.entrySet()) {
			hash += entry.getKey().hashCode();
			if (entry.getValue() != null)
				hash += entry.getValue().hashCode();
		}

		return hash;
	}

	/**
	 * Returns a hash code for this DIDURL object.
	 *
	 * @return a hash code value for this object
	 */
	@Override
	public int hashCode() {
		int hash = did.hashCode();
		hash += mapHashCode(parameters);
		hash += path == null ? 0 : path.hashCode();
		hash += mapHashCode(query);
		hash += fragment == null ? 0 : fragment.hashCode();

		return hash;
	}

	static class Serializer extends StdSerializer<DIDURL> {
		private static final long serialVersionUID = -5560151545310632117L;

		public Serializer() {
			this(null);
		}

		public Serializer(Class<DIDURL> t) {
			super(t);
		}

		@Override
		public void serialize(DIDURL id, JsonGenerator gen,
				SerializerProvider provider) throws IOException {
			SerializeContext context = (SerializeContext)provider.getConfig()
					.getAttributes().getAttribute(DIDEntity.CONTEXT_KEY);
			// TODO: checkme
			DID base = null;
			if (!context.isNormalized())
				base = context.getDid() != null ? context.getDid() : id.getDid();

			gen.writeString(id.toString(base));
		}
	}

	static class NormalizedSerializer extends StdSerializer<DIDURL> {
		private static final long serialVersionUID = -5560151545310632117L;

		public NormalizedSerializer() {
			this(null);
		}

		public NormalizedSerializer(Class<DIDURL> t) {
			super(t);
		}

		@Override
		public void serialize(DIDURL id, JsonGenerator gen,
				SerializerProvider provider) throws IOException {
			gen.writeString(id.toString());
		}
	}

	static class Deserializer extends StdDeserializer<DIDURL> {
		private static final long serialVersionUID = -3649714336670800081L;

		public Deserializer() {
			this(null);
		}

		public Deserializer(Class<Proof> t) {
			super(t);
		}

		@Override
		public DIDURL deserialize(JsonParser p, DeserializationContext ctxt)
				throws IOException, JsonProcessingException {
			JsonToken token = p.getCurrentToken();
			if (!token.equals(JsonToken.VALUE_STRING))
				throw ctxt.weirdStringException(p.getText(), DIDURL.class, "Invalid DIDURL");

			String url = p.getText().trim();
			return new DIDURL(null, url);
		}
	}

	class Listener extends DIDURLBaseListener {
		private String name;
		private String value;

		@Override
		public void exitMethod(DIDURLParser.MethodContext ctx) {
			String method = ctx.getText();
			if (!method.equals(DID.METHOD))
				throw new IllegalArgumentException("Unknown method: " + method);

			name = method;
		}

		@Override
		public void exitMethodSpecificString(
				DIDURLParser.MethodSpecificStringContext ctx) {
			value = ctx.getText();
		}

		@Override
		public void exitDid(DIDURLParser.DidContext ctx) {
			did = new DID(name, value);
			name = null;
			value = null;
		}

		@Override
		public void exitParamMethod(DIDURLParser.ParamMethodContext ctx) {
			String method = ctx.getText();
			if (!method.equals(DID.METHOD))
				throw new IllegalArgumentException(
						"Unknown parameter method: " + method);
		}

		@Override
		public void exitParamQName(DIDURLParser.ParamQNameContext ctx) {
			name = ctx.getText();
		}

		@Override
		public void exitParamValue(DIDURLParser.ParamValueContext ctx) {
			value = ctx.getText();
		}

		@Override
		public void exitParam(DIDURLParser.ParamContext ctx) {
			if (parameters == null)
				parameters = new LinkedHashMap<String, String>(8);

			parameters.put(name, value);

			name = null;
			value = null;
		}

		@Override
		public void exitPath(DIDURLParser.PathContext ctx) {
			path = "/" + ctx.getText();
		}

		@Override
		public void exitQueryParamName(DIDURLParser.QueryParamNameContext ctx) {
			name = ctx.getText();
		}

		@Override
		public void exitQueryParamValue(DIDURLParser.QueryParamValueContext ctx) {
			value = ctx.getText();
		}

		@Override
		public void exitQueryParam(DIDURLParser.QueryParamContext ctx) {
			if (query == null)
				query = new LinkedHashMap<String, String>(8);

			query.put(name, value);

			name = null;
			value = null;
		}

		@Override
		public void exitFrag(DIDURLParser.FragContext ctx) {
			fragment = ctx.getText();
		}
	}

	/**
	 * Builder class to create or modify a DIDURL.
	 */
	public static class Builder {
		private DIDURL url;

		/**
		 * Create DIDURL builder object with given url as default pattern.
		 *
		 * @param url a string representation of DIDURL
		 */
		public Builder(String url) {
			this(new DIDURL(url));
		}

		/**
		 * Create DIDURL builder object with given url as default pattern.
		 *
		 * @param url a DIDURL object
		 */
		public Builder(DIDURL url) {
			this.url = new DIDURL(url.getDid());
			this.url.parameters = new LinkedHashMap<String, String>(url.parameters);
			this.url.path = url.path;
			this.url.query = new LinkedHashMap<String, String>(url.query);
			this.url.fragment = url.fragment;
		}

		/**
		 * Create DIDURL builder object with given did as base DID.
		 *
		 * @param did a DID object as the base DID
		 */
		public Builder(DID did) {
			this(new DIDURL(did));
		}

		/**
		 * Set the base DID object of the DIDURL that to be build.
		 *
		 * @param did a DID object, could be null
		 * @return the builder instance for method chaining
		 */
		public Builder setDid(DID did) {
			url.setDid(did);
			return this;
		}

		/**
		 * Set the base DID object of the DIDURL that to be build.
		 *
		 * @param did a string representation of DID, could be null
		 * @return the builder instance for method chaining
		 */
		public Builder setDid(String did) {
			return setDid(DID.valueOf(did));
		}

		/**
		 * Sets a DID parameter with given value.
		 *
		 * @param name a DID parameter name
		 * @param value the parameter value
		 * @return the builder instance for method chaining
		 */
		public Builder setParameter(String name, String value) {
			checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");

			url.parameters.put(name, value);
			return this;
		}

		/**
		 * Sets DID parameters with given map object. All the previous
		 * parameters and values will be clear.
		 *
		 * @param params a string/string map object for DID parameters
		 * @return the builder instance for method chaining
		 */
		public Builder setParameters(Map<String, String> params) {
			url.parameters.clear();

			if (params != null && params.size() > 0)
				url.parameters.putAll(params);

			return this;
		}

		/**
		 * Remove the specific parameter from the DID parameters.
		 *
		 * @param name the parameter name to be remove
		 * @return the builder instance for method chaining
		 */
		public Builder removeParameter(String name) {
			checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");

			url.parameters.remove(name);

			return this;
		}

		/**
		 * Remove all the existing parameters from the DID parameters component.
		 *
		 * @return the builder instance for method chaining
		 */
		public Builder clearParameters() {
			url.parameters.clear();
			return this;
		}

		/**
		 * Set the path component of the DIDURL object.
		 *
		 * @param path a path string
		 * @return the builder instance for method chaining
		 */
		public Builder setPath(String path) {
			url.path = path == null || path.isEmpty() ? null : path;
			return this;
		}

		/**
		 * Sets a query parameter with given value.
		 *
		 * @param name a query parameter name
		 * @param value the parameter value
		 * @return the builder instance for method chaining
		 */
		public Builder setQueryParameter(String name, String value) {
			checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");

			url.query.put(name, value);
			return this;
		}

		/**
		 * Sets query parameters with given map object. All the previous
		 * parameters and values will be clear.
		 *
		 * @param params a string/string map object for query parameters
		 * @return the builder instance for method chaining
		 */
		public Builder setQueryParameters(Map<String, String> params) {
			url.query.clear();

			if (params != null && params.size() > 0)
				url.query.putAll(params);

			return this;
		}

		/**
		 * Remove the specific parameter from the query parameters.
		 *
		 * @param name the parameter name to be remove
		 * @return the builder instance for method chaining
		 */
		public Builder removeQueryParameter(String name) {
			checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");

			url.query.remove(name);
			return this;
		}

		/**
		 * Remove all the existing parameters from the query parameters component.
		 *
		 * @return the builder instance for method chaining
		 */
		public Builder clearQueryParameters() {
			url.query.clear();
			return this;
		}

		/**
		 * Set the fragment component.
		 *
		 * @param fragment a fragment string
		 * @return the builder instance for method chaining
		 */
		public Builder setFragment(String fragment) {
			url.fragment = fragment == null || fragment.isEmpty() ? null : fragment;
			return this;
		}

		/**
		 * Get the DIDURL instance that created by this builder object.
		 *
		 * <p>
		 * After build a DIDURL object from this Builder object,
		 * the builder still available with the same status that before call
		 * the build method.
		 * </p>
		 *
		 * @return a DIDURL object
		 */
		public DIDURL build() {
			return new DIDURL(url);
		}
	}
}
