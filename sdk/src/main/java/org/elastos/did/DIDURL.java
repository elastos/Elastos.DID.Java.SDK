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
	private DID did;
	private String path;
	private Map<String, String> query;
	private String queryString;
	private String fragment;

	private String repr;

	private AbstractMetadata metadata;

	/**
	 * Constructs a DIDURL object with the given DID context and a url string.
	 *
	 * @param context a DID context of the DIDURL object, if the url is a relative DIDURL
	 * @param url a string representation of DIDURL
	 * @throws MalformedDIDURLException if the url in wrong syntax
	 */
	public DIDURL(DID context, String url) throws MalformedDIDURLException {
		Parser parser = new Parser();
		parser.parse(context, url);
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
	 * Constructs a DIDURL object with the given DID context and a DIDURL object.
	 *
	 * @param context a DID context of the DIDURL object, if the url is a relative DIDURL
	 * @param url a DIDURL object
	 */
	public DIDURL(DID context, DIDURL url) {
		checkArgument(context != null || url != null, "Invalid context and url");

		if (context != null)
			this.did = context;

		if (url != null) {
			if (url.did != null)
				this.did = url.did;
			this.path = url.path;
			this.query = url.query;
			this.queryString = url.queryString;
			this.fragment = url.fragment;
			this.repr = url.repr;
			this.metadata = url.metadata;
		} else {
			this.query = Collections.emptyMap();
		}
	}

	/**
	 * Constructs a DIDURL object from DID object.
	 *
	 * @param did a DID context of the DIDURL object
	 */
	private DIDURL(DID context) {
		this(context, (DIDURL)null);
	}

	private DIDURL() {
	}

	private DIDURL deepClone(boolean readonly) {
		DIDURL result = new DIDURL();
		result.did = this.did;
		result.path = this.path;
		result.query = (this.query.isEmpty() && readonly) ? Collections.emptyMap() :
				new LinkedHashMap<String, String>(this.query);
		result.queryString = this.queryString;
		result.fragment = this.fragment;
		result.repr = this.repr;

		return result;
	}

	/**
	 * Create a DIDURL object from the given string. The method will parse the
	 * DIDURL object from the string if the string is not empty. Otherwise
	 * will return null. If the parsed DIDURL object is relative, then use
	 * context as it's base DID.
	 *
	 * @param context a DID context of the DIDURL object, if the url is a relative DIDURL
	 * @param url a string representation of DIDURL
	 * @return a DIDURL object if url isn't null or empty; otherwise null
	 * @throws MalformedDIDURLException if the url in wrong syntax
	 */
	public static DIDURL valueOf(DID context, String url) throws MalformedDIDURLException {
		return (url == null || url.isEmpty()) ? null : new DIDURL(context, url);
	}

	/**
	 * Create a DIDURL object from the given string. The method will parse the
	 * DIDURL object from the string if the string is not empty. Otherwise
	 * will return null. If the parsed DIDURL object is relative, then use
	 * context as it's base DID.
	 *
	 * @param context a DID context of the DIDURL object, if the url is a relative DIDURL
	 * @param url a string representation of DIDURL
	 * @return a DIDURL object if url isn't null or empty; otherwise null
	 * @throws MalformedDIDURLException if the url in wrong syntax
	 */
	public static DIDURL valueOf(String context, String url) throws MalformedDIDURLException {
		return (url == null || url.isEmpty()) ? null : new DIDURL(DID.valueOf(context), url);
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

		if (queryString == null)
			queryString = mapToString(query, "&");

		return queryString;
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
	 * Check if the DIDURL object is full qualified.
	 *
	 * @return true if the DIDURL is qualified, false otherwise
	 */
	public boolean isQualified() {
		return (did != null && fragment != null);
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
	 * @param context a context DID reference object for relative DIDURL
	 * @return a relative string representation of this DIDURL object
	 */
	protected String toString(DID context) {
		StringBuilder builder = new StringBuilder(512);
		if (did != null && (context == null || !did.equals(context)))
			builder.append(did);

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
		if (repr == null)
			repr = toString(null);

		return repr;
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

	/**
	 * Returns a hash code for this DIDURL object.
	 *
	 * @return a hash code value for this object
	 */
	@Override
	public int hashCode() {
		return toString().hashCode();
	}

	/* =========================================================================
	 *
	 * DID and DIDURL syntax definition
	 *
	 * did:elastos:method-specific-string[;params][/path][?query][#fragment]
	 *
	 * didurl
	 *   : did? ('/' path)? ('?' query)? ('#' fragment)? SPACE?
	 *   ;
	 *
	 * did
	 *   : 'did' ':' method ':' methodSpecificString
	 *   ;
	 *
	 * method
	 *   : STRING
	 *   ;
	 *
	 * methodSpecificString
	 *   : STRING
	 *   ;
	 *
	 * path
	 *   : STRING ('/' STRING)*
	 *   ;
	 *
	 * query
	 *   : queryParam ('&' queryParam)*
	 *   ;
	 *
	 * queryParam
	 *   : queryParamName ('=' queryParamValue)?
	 *   ;
	 *
	 * queryParamName
	 *   : STRING
	 *   ;
	 *
	 * queryParamValue
	 *   : STRING
	 *   ;
	 *
	 * fragment
	 *   : STRING
	 *   ;
	 *
	 * STRING
	 *   : ([a-zA-Z~0-9] | HEX) ([a-zA-Z0-9._\-] | HEX)*
	 *   ;
	 *
	 * HEX
	 *   : ('%' [a-fA-F0-9] [a-fA-F0-9])+
	 *   ;
	 *
	 * SPACE
	 *   : [ \t\n\r]+
	 *   ;
	 *
	 =========================================================================*/

	class Parser {
		private boolean isHexChar(char ch) {
			return ((ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f') ||
					(ch >= '0' && ch <= '9'));
		}

		private boolean isTokenChar(char ch, boolean start) {
			if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
					(ch >= '0' && ch <= '9'))
				return true;

			if (start)
				return false;
			else
				return (ch  == '.' || ch == '_' || ch == '-');
		}

		private int scanNextPart(String url, int start, int limit,
				String partSeps, String tokenSeps) throws MalformedDIDURLException {
			int nextPart = limit;

			boolean tokenStart = true;

			for (int i = start; i < limit; i++) {
				char ch = url.charAt(i);

				if (partSeps != null && partSeps.indexOf(ch) >= 0) {
					nextPart = i;
					break;
				}

				if (tokenSeps != null && tokenSeps.indexOf(ch) >= 0) {
					if (tokenStart)
						throw new MalformedDIDURLException("Invalid char at: " + i);

					tokenStart = true;
					continue;
				}

				if (isTokenChar(ch, tokenStart)) {
					tokenStart = false;
					continue;
				}

				if (ch == '%') {
					if (i + 2 >= limit)
						throw new MalformedDIDURLException("Invalid char at: " + i);

					char seq = url.charAt(++i);
					if (!isHexChar(seq))
						throw new MalformedDIDURLException("Invalid hex char at: " + i);

					seq = url.charAt(++i);
					if (!isHexChar(seq))
						throw new MalformedDIDURLException("Invalid hex char at: " + i);

					tokenStart = false;
					continue;
				}

				throw new MalformedDIDURLException("Invalid char at: " + i);
			}

			return nextPart;
		}

		public void parse(DID context, String url) throws MalformedDIDURLException {
			DIDURL.this.did = context;

			if (url == null)
				throw new MalformedDIDURLException("null DIDURL string");

			int start = 0;
			int limit = url.length();
			int nextPart;

			// trim the leading and trailing spaces
			while ((limit > 0) && (url.charAt(limit - 1) <= ' '))
				limit--;		//eliminate trailing whitespace

			while ((start < limit) && (url.charAt(start) <= ' '))
				start++;		// eliminate leading whitespace

			if (start == limit) // empty url string
				throw new MalformedDIDURLException("empty DIDURL string");

			int pos = start;

			// DID
			if (pos < limit && url.regionMatches(pos, "did:", 0, 4)) {
				nextPart = scanNextPart(url, pos, limit, "/?#", ":");
				try {
					DIDURL.this.did = new DID(url, pos, nextPart);
				} catch (Exception e) {
					throw new MalformedDIDURLException("Invalid did at: " + pos, e);
				}

				pos = nextPart;
			}

			// path
			if (pos < limit && url.charAt(pos) == '/') {
				nextPart = scanNextPart(url, pos + 1, limit, "?#", "/");
				DIDURL.this.path = url.substring(pos, nextPart);
				pos = nextPart;
			}

			// query
			if (pos < limit && url.charAt(pos) == '?') {
				nextPart = scanNextPart(url, pos + 1, limit, "#", "&=");
				String queryString = url.substring(pos + 1, nextPart);
				pos = nextPart;

				if (!queryString.isEmpty()) {
					Map<String, String> query = new LinkedHashMap<String, String>();

					String[] pairs = queryString.split("&");
					for (String pair : pairs) {
						String[] parts = pair.split("=");
						if (parts.length > 0 && !parts[0].isEmpty()) {
							String name = parts[0];
							String value = parts.length == 2 ? parts[1] : null;
							query.put(name, value);
						}
					}

					DIDURL.this.query = query;
				}
			} else {
				DIDURL.this.query = Collections.emptyMap();
			}

			// fragment
			// condition: pos == start
			//	Compatible with v1, support fragment without leading '#'
			if ((pos < limit && url.charAt(pos) == '#') || (pos == start)) {
				if (url.charAt(pos) == '#')
					pos++;

				nextPart = scanNextPart(url, pos, limit, "", null);
				String fragment = url.substring(pos, nextPart);
				if (!fragment.isEmpty())
					DIDURL.this.fragment = fragment;
			}
		}
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
			return url.isEmpty() ? null : new DIDURL(null, url);
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
		 * @param url a DIDURL object
		 */
		public Builder(DIDURL url) {
			this.url = url.deepClone(false);
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
			return url.deepClone(true);
		}
	}
}
