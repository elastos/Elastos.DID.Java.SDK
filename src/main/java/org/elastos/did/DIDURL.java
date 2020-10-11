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

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import org.elastos.did.DIDObject.SerializeContext;
import org.elastos.did.VerifiableCredential.Proof;
import org.elastos.did.exception.DIDStoreException;
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
	private DID did;
	private Map<String, String> parameters;
	private String path;
	private Map<String, String> query;
	private String fragment;

	private CredentialMetadata metadata;

	/**
	 * Constructs the DIDURl with the given value.
	 *
	 * @param base the owner of DIDURL
	 * @param url the DIDURl string
	 */
	public DIDURL(DID base, String url) {
		if (url == null || url.isEmpty())
			throw new IllegalArgumentException();

		if (url != null) {
			if (url.startsWith("did:")) {
				ParserHelper.parse(url, false, new Listener());
				if (base != null && !getDid().equals(base))
					throw new IllegalArgumentException("Mismatched arguments");

				return;
			}

			if (url.startsWith("#"))
				url = url.substring(1);
		}

		this.did = base;
		this.fragment = url;
	}

	/**
	 * Constructs the DIDURl with the given value.
	 *
	 * @param url the DIDURl string
	 * @throws MalformedDIDURLException DIDURL is malformed.
	 */
	public DIDURL(String url) throws MalformedDIDURLException {
		if (url == null || url.isEmpty())
			throw new IllegalArgumentException();

		try {
			ParserHelper.parse(url, false, new Listener());
		} catch(IllegalArgumentException e) {
			throw new MalformedDIDURLException(e.getMessage());
		}
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
		if (did == null)
			throw new IllegalArgumentException();

		this.did = did;
	}

	private String mapToString(Map<String, String> map, String sep) {
		boolean init = true;
		if (map == null)
			return null;

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
	public String getParameters() {
		return mapToString(parameters, ";");
	}

	/**
	 * Get the parameter according to the given name.
	 *
	 * @param name the name string
 	 * @return the parameter string
	 */
	public String getParameter(String name) {
		if (parameters == null)
			return null;

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
		if (parameters == null)
			return false;

		return parameters.containsKey(name);
	}

	/**
	 * Add parameter.
	 *
	 * @param name the parameter's name
	 * @param value the parameter's value
	 */
	protected void addParameter(String name, String value) {
		parameters.put(name, value);
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
	 * Set path to DIDURL.
	 *
	 * @param path the path string
	 */
	protected void setPath(String path) {
		this.path = path;
	}

	/**
	 * Get query of DIDURL.
	 *
	 * @return the query string
	 */
	public String getQuery() {
		return mapToString(query, "&");
	}

	/**
	 * Get 'name' query parameter.
	 *
	 * @param name the name string
	 * @return the value string
	 */
	public String getQueryParameter(String name) {
		if (query == null)
			return null;

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
		if (query == null)
			return false;

		return query.containsKey(name);
	}

	/**
	 * Add query parameter.
	 *
	 * @param name the name string of parameter
	 * @param value the value string of parameter
	 */
	protected void addQueryParameter(String name, String value) {
		query.put(name, value);
	}

	/**
	 * Get fragmengt string of DIDURL.
	 *
	 * @return the fragment string
	 */
	public String getFragment() {
		return fragment;
	}

	/**
	 * Set fragment string of DIDURL.
	 *
	 * @param fragment the fragment string
	 */
	protected void setFragment(String fragment) {
		this.fragment = fragment;
	}

	/**
	 * Set meta data for Credential.
	 *
	 * @param metadata the meta data
	 */
	protected void setMetadata(CredentialMetadata metadata) {
		this.metadata = metadata;
	}

	/**
	 * Get meta data from Credential.
	 *
	 * @return the meta data
	 */
	public CredentialMetadata getMetadata() {
		if (metadata == null)
			metadata = new CredentialMetadata();

		return metadata;
	}

	/**
	 * Store meta data in DIDStore.
	 *
	 * @throws DIDStoreException there is no store to attatch.
	 */
	public void saveMetadata() throws DIDStoreException {
		if (metadata != null && metadata.attachedStore())
			metadata.getStore().storeCredentialMetadata(this.getDid(), this, metadata);
	}

	public String toString(DID base) {
		StringBuilder builder = new StringBuilder(512);
		if (did != null && (base == null || !did.equals(base)))
			builder.append(did);

		if (parameters != null && !parameters.isEmpty())
			builder.append(";").append(getParameters());

		if (path != null && !path.isEmpty())
			builder.append(path);

		if (query != null && !query.isEmpty())
			builder.append("?").append(getQuery());

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
		return toString().compareTo(id.toString());
	}

	private int mapHashCode(Map<String, String> map) {
		int hash = 0;

		if (map == null)
			return hash;

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
					.getAttributes().getAttribute(DIDObject.CONTEXT_KEY);
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
		public void enterDid(DIDURLParser.DidContext ctx) {
			did = new DID();
		}

		@Override
		public void exitMethod(DIDURLParser.MethodContext ctx) {
			String method = ctx.getText();
			if (!method.equals(DID.METHOD))
				throw new IllegalArgumentException("Unknown method: " + method);

			did.setMethod(DID.METHOD);
		}

		@Override
		public void exitMethodSpecificString(
				DIDURLParser.MethodSpecificStringContext ctx) {
			did.setMethodSpecificId(ctx.getText());
		}

		@Override
		public void enterParams(DIDURLParser.ParamsContext ctx) {
			parameters = new LinkedHashMap<String, String>(8);
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
			addParameter(name, value);
			name = null;
			value = null;
		}

		@Override
		public void exitPath(DIDURLParser.PathContext ctx) {
			setPath("/" + ctx.getText());
		}

		@Override
		public void enterQuery(DIDURLParser.QueryContext ctx) {
			query = new LinkedHashMap<String, String>(8);
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
			addQueryParameter(name, value);
			name = null;
			value = null;
		}

		@Override
		public void exitFrag(DIDURLParser.FragContext ctx) {
			fragment = ctx.getText();
		}
	}
}
