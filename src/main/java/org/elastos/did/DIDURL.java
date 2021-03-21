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
 * DID URL defines by the did-url rule, refers to a URL that begins with a DID
 * followed by one or more additional components.
 * <p>
 * A DID URL always identifies the resource to be located.
 * DIDURL includes DID and Url fragment by user defined.
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
	 * Constructs the DIDURl with the given value.
	 *
	 * @param base the owner of DIDURL
	 * @param url the DIDURl string
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
	 * Constructs the DIDURl with the given value.
	 *
	 * @param url the DIDURl string
	 * @throws MalformedDIDURLException DIDURL is malformed.
	 */
	public DIDURL(String url) throws MalformedDIDURLException {
		this(null, url);
	}

	public DIDURL(DID baseRef, DIDURL url) {
		checkArgument(url != null, "Invalid url");

		this.did = url.did == null ? baseRef : url.did;
		this.parameters = url.parameters;
		this.path = url.path;
		this.query = url.query;
		this.fragment = url.fragment;
		this.metadata = url.metadata;
	}

	public DIDURL(DID did) {
		this.did = did;
		this.parameters = Collections.emptyMap();
		this.query = Collections.emptyMap();
	}

	// Deep-copy constructor
	private DIDURL(DIDURL url) {
		this.did = url.did;
		this.parameters = url.parameters.isEmpty() ? Collections.emptyMap() :
				new LinkedHashMap<String, String>(url.parameters);
		this.path = url.path;
		this.query = url.query.isEmpty() ? Collections.emptyMap() :
				new LinkedHashMap<String, String>(url.query);
		this.fragment = url.fragment;
	}

	public static DIDURL valueOf(DID baseRef, String url) throws MalformedDIDURLException {
		return (url == null || url.isEmpty()) ? null : new DIDURL(baseRef, url);
	}

	public static DIDURL valueOf(String baseRef, String url) throws MalformedDIDURLException {
		return (url == null || url.isEmpty()) ? null : new DIDURL(DID.valueOf(baseRef), url);
	}

	public static DIDURL valueOf(String url) throws MalformedDIDURLException {
		return (url == null || url.isEmpty()) ? null : new DIDURL(url);
	}

	/**
	 * Get owner of DIDURL.
	 *
	 * @return the DID object
	 */
	public DID getDid() {
		return did;
	}

	/**
	 * Set DID to DIDURL.
	 *
	 * @param did the DID Object
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
	 * Get all parameters.
	 *
	 * @return the parameters string
	 */
	public String getParametersString() {
		if (parameters.isEmpty())
			return null;

		return mapToString(parameters, ";");
	}

	public Map<String, String> getParameters() {
		return Collections.unmodifiableMap(parameters);
	}

	/**
	 * Get the parameter according to the given name.
	 *
	 * @param name the name string
 	 * @return the parameter string
	 */
	public String getParameter(String name) {
		checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");
		return parameters.get(name);
	}

	/**
	 * Judge whether there is 'name' parameter in DIDStorage.
	 *
	 * @param name the key of parameter
	 * @return the returned value is true if there is 'name' parameter;
	 *         the returned value is true if there is no 'name' parameter.
	 */
	public boolean hasParameter(String name) {
		checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");
		return parameters.containsKey(name);
	}

	/**
	 * Get the path of DIDURL.
	 *
	 * @return the path string
	 */
	public String getPath() {
		return path;
	}

	/**
	 * Get query of DIDURL.
	 *
	 * @return the query string
	 */
	public String getQueryString() {
		if (query.isEmpty())
			return null;

		return mapToString(query, "&");
	}

	public Map<String, String> getQuery() {
		return Collections.unmodifiableMap(query);
	}

	/**
	 * Get 'name' query parameter.
	 *
	 * @param name the name string
	 * @return the value string
	 */
	public String getQueryParameter(String name) {
		checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");
		return query.get(name);
	}

	/**
	 * Judge whether there is 'name' parameter
	 *
	 * @param name the name string
	 * @return the returned value is true if there is 'name' parameter;
	 *         the returned value is true if there is no 'name' parameter.
	 */
	public boolean hasQueryParameter(String name) {
		checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");
		return query.containsKey(name);
	}

	/**
	 * Get fragment string of DIDURL.
	 *
	 * @return the fragment string
	 */
	public String getFragment() {
		return fragment;
	}

	/**
	 * Set meta data for Credential.
	 *
	 * @param metadata the meta data
	 */
	protected void setMetadata(AbstractMetadata metadata) {
		this.metadata = metadata;
	}

	/**
	 * Get meta data from Credential.
	 *
	 * @return the meta data
	 */
	public AbstractMetadata getMetadata() {
		return metadata;
	}

	public String toString(DID base) {
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

	@Override
	public String toString() {
		return toString(null);
	}

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

	public static class Builder {
		private DIDURL url;

		public Builder(String url) {
			this(new DIDURL(url));
		}

		public Builder(DIDURL url) {
			this.url = new DIDURL(url.getDid());
			this.url.parameters = new LinkedHashMap<String, String>(url.parameters);
			this.url.path = url.path;
			this.url.query = new LinkedHashMap<String, String>(url.query);
			this.url.fragment = url.fragment;
		}

		public Builder(DID did) {
			this(new DIDURL(did));
		}

		public Builder setDid(DID did) {
			checkArgument(did != null, "Invalid did");

			url.setDid(did);
			return this;
		}

		public Builder setDid(String did) {
			return setDid(DID.valueOf(did));
		}

		public Builder clearDid() {
			url.setDid(null);
			return this;
		}

		public Builder setParameter(String name, String value) {
			checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");

			url.parameters.put(name, value);
			return this;
		}

		public Builder setParameters(Map<String, String> params) {
			url.parameters.clear();

			if (params != null && params.size() > 0)
				url.parameters.putAll(params);

			return this;
		}

		public Builder removeParameter(String name) {
			checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");

			url.parameters.remove(name);

			return this;
		}

		public Builder clearParameters() {
			url.parameters.clear();
			return this;
		}

		public Builder setPath(String path) {
			url.path = path == null || path.isEmpty() ? null : path;
			return this;
		}

		public Builder clearPath() {
			url.path = null;
			return this;
		}

		public Builder setQueryParameter(String name, String value) {
			checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");

			url.query.put(name, value);
			return this;
		}

		public Builder setQueryParameters(Map<String, String> params) {
			url.query.clear();

			if (params != null && params.size() > 0)
				url.query.putAll(params);

			return this;
		}

		public Builder removeQueryParameter(String name) {
			checkArgument(name != null && !name.isEmpty(), "Invalid parameter name");

			url.query.remove(name);
			return this;
		}

		public Builder clearQueryParameters() {
			url.query.clear();
			return this;
		}

		public Builder setFragment(String fragment) {
			url.fragment = fragment == null || fragment.isEmpty() ? null : fragment;
			return this;
		}

		public Builder clearFragment() {
			url.fragment = null;
			return this;
		}

		public DIDURL build() {
			return new DIDURL(url);
		}
	}
}
