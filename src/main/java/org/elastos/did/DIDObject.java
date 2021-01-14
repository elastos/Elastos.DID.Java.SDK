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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.elastos.did.exception.DIDSyntaxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Base class for all DID objects.
 */
public abstract class DIDObject<T> {
	private final static boolean NORMALIZED_DEFAULT = false;

	protected final static SimpleDateFormat dateFormat =
			new SimpleDateFormat(Constants.DATE_FORMAT);

	protected final static SimpleDateFormat isoDateFormat =
			new SimpleDateFormat(Constants.DATE_FORMAT_ISO_8601);

	private static final Logger log = LoggerFactory.getLogger(DIDObject.class);

	protected final static String CONTEXT_KEY = "org.elastos.did.context";

	static {
		dateFormat.setTimeZone(Constants.UTC);
		isoDateFormat.setTimeZone(Constants.UTC);
	}

	protected static class SerializeContext {
		private boolean normalized;
		private DID did;

		protected SerializeContext() {
			this(false, null);
		}

		protected SerializeContext(boolean normalized, DID did) {
			this.normalized = normalized;
			this.did = did;
		}

		public boolean isNormalized() {
			return normalized;
		}

		public SerializeContext setNormalized(boolean normalized) {
			this.normalized = normalized;
			return this;
		}

		public DID getDid() {
			return did;
		}

		public void setDid(DID did) {
			this.did = did;
		}
	}

	static class DateDeserializer extends StdDeserializer<Date> {
		private static final long serialVersionUID = -4252894239212420927L;

		public DateDeserializer() {
	        this(null);
	    }

	    public DateDeserializer(Class<?> t) {
	        super(t);
	    }

		@Override
		public Date deserialize(JsonParser p, DeserializationContext ctxt)
				throws IOException, JsonProcessingException {
	    	JsonToken token = p.getCurrentToken();
	    	if (!token.equals(JsonToken.VALUE_STRING))
	    		throw ctxt.weirdStringException(p.getText(),
	    				Date.class, "Invalid datetime string");

	    	String dateStr = p.getValueAsString();
			try {
				return dateFormat.parse(dateStr);
			} catch (ParseException ignore) {
			}

			// Fail-back to ISO 8601 format.
			try {
				return isoDateFormat.parse(dateStr);
			} catch (ParseException e) {
				throw ctxt.weirdStringException(p.getText(),
	    				Date.class, "Invalid datetime string");
			}
		}
	}

	/**
	 * Get current object's DID context.
	 *
	 * @return the DID object or null
	 */
	protected DID getSerializeContextDid() {
		return null;
	}

	/**
	 * Post sanitize routine after deserialization.
	 *
	 * @throws DIDSyntaxException if the DID object is invalid
	 */
	protected void sanitize() throws DIDSyntaxException {
		sanitize(true);
	}

	/**
	 * Sanitize routine before sealing or after deserialization.
	 *
	 * @param withProof check the proof object or not. Normally, when withProof
	 *                  is true, it means that the post check after
	 *                  deserialization; when withProof is false, it means that
	 *                  the check before sealing the DID object
	 * @throws DIDSyntaxException if the DID object is invalid
	 */
	protected void sanitize(boolean withProof) throws DIDSyntaxException {
	}

	/**
	 * Get the ObjectMapper for serialization or deserialization.
	 *
	 * @return the ObjectMapper instance.
	 */
	protected static ObjectMapper getObjectMapper() {
		JsonFactory jsonFactory = new JsonFactory();
		jsonFactory.configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false);
		jsonFactory.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, false);

		ObjectMapper mapper = new ObjectMapper(jsonFactory);

		mapper.disable(MapperFeature.AUTO_DETECT_CREATORS,
				MapperFeature.AUTO_DETECT_FIELDS,
				MapperFeature.AUTO_DETECT_GETTERS,
				MapperFeature.AUTO_DETECT_SETTERS,
				MapperFeature.AUTO_DETECT_IS_GETTERS);

		// Make the ObjectMapper handle the datetime string correctly
		mapper.setDateFormat(dateFormat);
		SimpleModule didModule = new SimpleModule();
		didModule.addDeserializer(Date.class, new DateDeserializer());
		mapper.registerModule(didModule);

		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

		return mapper;
	}

	/**
	 * Get the ObjectMapper for serialization.
	 *
	 * @param normalized if normalized output, ignored when the sign is true
	 * @return the ObjectMapper instance
	 */
	private ObjectMapper getObjectMapper(boolean normalized) {
		ObjectMapper mapper = getObjectMapper();

		mapper.setConfig(mapper.getSerializationConfig().withAttribute(CONTEXT_KEY,
				new SerializeContext(normalized, getSerializeContextDid())));

		return mapper;
	}

	/**
	 * Generic method to parse a DID object from a JSON node
	 * representation into given DIDObject type.
	 *
	 * @param <T> the generic DID object type
	 * @param content the JSON node for building the object
	 * @param clazz the class object for DID object
	 * @return the parsed DID object
	 * @throws DIDSyntaxException if a parse error occurs
	 */
	protected static<T extends DIDObject<?>> T parse(JsonNode content, Class<T> clazz)
			throws DIDSyntaxException {
		ObjectMapper mapper = getObjectMapper();

		try {
			T o = mapper.treeToValue(content, clazz);
			o.sanitize();
			return o;
		} catch (IOException e) {
			throw DIDSyntaxException.instantiateFor(clazz, e.getMessage(), e);
		}
	}

	/**
	 * Generic method to parse a DID object from a string JSON
	 * representation into given DIDObject type.
	 *
	 * @param <T> the generic DID object type
	 * @param content the string JSON content for building the object
	 * @param clazz the class object for DID object
	 * @return the parsed DID object
	 * @throws DIDSyntaxException if a parse error occurs
	 */
	public static<T extends DIDObject<?>> T parse(String content, Class<T> clazz)
			throws DIDSyntaxException {
		ObjectMapper mapper = getObjectMapper();

		try {
			T o = mapper.readValue(content, clazz);
			o.sanitize();
			return o;
		} catch (IOException e) {
			throw DIDSyntaxException.instantiateFor(clazz, e.getMessage(), e);
		}
	}

	/**
	 * Generic method to parse a DID object from a Reader object
	 * into given DIDObject type.
	 *
	 * @param <T> the generic DID object type
	 * @param src Reader object used to read JSON content for building the object
	 * @param clazz the class object for DID object
	 * @return the parsed DID object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static<T extends DIDObject<?>> T parse(Reader src, Class<T> clazz)
			throws DIDSyntaxException, IOException {
		ObjectMapper mapper = getObjectMapper();

		try {
			T o = mapper.readValue(src, clazz);
			o.sanitize();
			return o;
		} catch (JsonProcessingException e) {
			throw DIDSyntaxException.instantiateFor(clazz, e.getMessage(), e);
		}
	}

	/**
	 * Generic method to parse a DID object from a InputStream object
	 * into given DIDObject type.
	 *
	 * @param <T> the generic DID object type
	 * @param src InputStream object used to read JSON content for building the object
	 * @param clazz the class object for DID object
	 * @return the parsed DID object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static<T extends DIDObject<?>> T parse(InputStream src, Class<T> clazz)
			throws DIDSyntaxException, IOException {
		ObjectMapper mapper = getObjectMapper();

		try {
			T o = mapper.readValue(src, clazz);
			o.sanitize();
			return o;
		} catch (JsonProcessingException e) {
			throw DIDSyntaxException.instantiateFor(clazz, e.getMessage(), e);
		}
	}

	/**
	 * Generic method to parse a DID object from a File object
	 * into given DIDObject type.
	 *
	 * @param <T> the generic DID object type
	 * @param src File object used to read JSON content for building the object
	 * @param clazz the class object for DID object
	 * @return the parsed DID object
	 * @throws DIDSyntaxException if a parse error occurs
	 * @throws IOException if an IO error occurs
	 */
	public static<T extends DIDObject<?>> T parse(File src, Class<T> clazz)
			throws DIDSyntaxException, IOException {
		ObjectMapper mapper = getObjectMapper();

		try {
			T o = mapper.readValue(src, clazz);
			o.sanitize();
			return o;
		} catch (JsonProcessingException e) {
			throw DIDSyntaxException.instantiateFor(clazz, e.getMessage(), e);
		}
	}

	/**
	 * Serialize DID object to a JSON string.
	 *
	 * @param normalized whether normalized output
	 * @return the serialized JSON string
	 * @throws DIDSyntaxException if a serialization error occurs
	 */
	public String serialize(boolean normalized) throws DIDSyntaxException {
		try {
			return getObjectMapper(normalized).writeValueAsString(this);
		} catch (JsonProcessingException e) {
			throw DIDSyntaxException.instantiateFor(getClass(), e.getMessage(), e);
		}
	}

	/**
	 * Serialize DID object to a JSON string.
	 *
	 * @return the serialized JSON string
	 * @throws DIDSyntaxException if a serialization error occurs
	 */
	public String serialize() throws DIDSyntaxException {
		return serialize(NORMALIZED_DEFAULT);
	}

	/**
	 * Serialize DID object to a Writer.
	 *
	 * @param out the output writer object
	 * @param normalized whether normalized output
	 * @throws DIDSyntaxException  if a serialization error occurs
	 * @throws IOException if an IO error occurs
	 */
	public void serialize(Writer out, boolean normalized)
			throws DIDSyntaxException, IOException {
		try {
			getObjectMapper(normalized).writeValue(out, this);
		} catch (JsonProcessingException e) {
			throw DIDSyntaxException.instantiateFor(getClass(), e.getMessage(), e);
		}
	}

	/**
	 * Serialize DID object to a Writer.
	 *
	 * @param out the output writer object
	 * @throws DIDSyntaxException  if a serialization error occurs
	 * @throws IOException if an IO error occurs
	 */
	public void serialize(Writer out) throws DIDSyntaxException, IOException {
		serialize(out, NORMALIZED_DEFAULT);
	}

	/**
	 * Serialize DID object to an OutputStream.
	 *
	 * @param out the output stream object
	 * @param normalized whether normalized output
	 * @throws DIDSyntaxException  if a serialization error occurs
	 * @throws IOException if an IO error occurs
	 */
	public void serialize(OutputStream out, boolean normalized)
			throws DIDSyntaxException, IOException {
		try {
			getObjectMapper(normalized).writeValue(out, this);
		} catch (JsonProcessingException e) {
			throw DIDSyntaxException.instantiateFor(getClass(), e.getMessage(), e);
		}
	}

	/**
	 * Serialize DID object to an OutputStream.
	 *
	 * @param out the output stream object
	 * @throws DIDSyntaxException  if a serialization error occurs
	 * @throws IOException if an IO error occurs
	 */
	public void serialize(OutputStream out) throws DIDSyntaxException, IOException {
		serialize(out, NORMALIZED_DEFAULT);
	}

	/**
	 * Serialize DID object to a file.
	 *
	 * @param out the output file object
	 * @param normalized whether normalized output
	 * @throws DIDSyntaxException  if a serialization error occurs
	 * @throws IOException if an IO error occurs
	 */
	public void serialize(File out, boolean normalized)
			throws DIDSyntaxException, IOException {
		try {
			getObjectMapper(normalized).writeValue(out, this);
		} catch (JsonProcessingException e) {
			throw DIDSyntaxException.instantiateFor(getClass(), e.getMessage(), e);
		}
	}

	/**
	 * Serialize DID object to a file.
	 *
	 * @param out the output file object
	 * @throws DIDSyntaxException  if a serialization error occurs
	 * @throws IOException if an IO error occurs
	 */
	public void serialize(File out) throws DIDSyntaxException, IOException {
		serialize(out, NORMALIZED_DEFAULT);
	}

	/**
	 * Get the JSON string representation of the object.
	 *
	 * @param normalized whether normalized output
	 * @return a JSON string representation of the object
	 */
	public String toString(boolean normalized) {
		try {
			return serialize(normalized);
		} catch (DIDSyntaxException ignore) {
			log.error("INTERNAL - Serialize to string.", ignore);
			return "";
		}
	}

	/**
	 * Get the JSON string representation of the object.
	 *
	 * @return a JSON string representation of the object
	 */
	@Override
	public String toString() {
		return toString(NORMALIZED_DEFAULT);
	}

	/**
	 * Serialize DID object to a JSON string.
	 *
	 * @param normalized whether normalized output
	 * @return the serialized JSON string
	 * @throws DIDSyntaxException if a serialization error occurs
	 * @deprecated use {@link #serialize(boolean)} instead
	 */
	@Deprecated
	public String toJson(boolean normalized) throws DIDSyntaxException {
		return serialize(normalized);
	}

	/**
	 * Serialize DID object to a JSON string.
	 *
	 * @return the serialized JSON string
	 * @throws DIDSyntaxException if a serialization error occurs
	 * @deprecated use {@link #serialize()} instead
	 */
	@Deprecated
	public String toJson() throws DIDSyntaxException {
		return serialize();
	}

	/**
	 * Serialize DID object to a Writer.
	 *
	 * @param out the output writer object
	 * @param normalized whether normalized output
	 * @throws DIDSyntaxException  if a serialization error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #serialize(Writer, boolean)} instead
	 */
	@Deprecated
	public void toJson(Writer out, boolean normalized)
			throws DIDSyntaxException, IOException {
		serialize(out, normalized);
	}

	/**
	 * Serialize DID object to a Writer.
	 *
	 * @param out the output writer object
	 * @throws DIDSyntaxException  if a serialization error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #serialize(Writer)} instead
	 */
	@Deprecated
	public void toJson(Writer out) throws DIDSyntaxException, IOException {
		serialize(out);
	}

	/**
	 * Serialize DID object to an OutputStream.
	 *
	 * @param out the output stream object
	 * @param normalized whether normalized output
	 * @throws DIDSyntaxException  if a serialization error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #serialize(OutputStream, boolean)} instead
	 */
	@Deprecated
	public void toJson(OutputStream out, boolean normalized)
			throws DIDSyntaxException, IOException {
		serialize(out, normalized);
	}

	/**
	 * Serialize DID object to an OutputStream.
	 *
	 * @param out the output stream object
	 * @throws DIDSyntaxException  if a serialization error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #serialize(OutputStream)} instead
	 */
	@Deprecated
	public void toJson(OutputStream out) throws DIDSyntaxException, IOException {
		serialize(out);
	}

	/**
	 * Serialize DID object to a file.
	 *
	 * @param out the output file object
	 * @param normalized whether normalized output
	 * @throws DIDSyntaxException  if a serialization error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #serialize(File, boolean)} instead
	 */
	@Deprecated
	public void toJson(File out, boolean normalized)
			throws DIDSyntaxException, IOException {
		serialize(out, normalized);
	}

	/**
	 * Serialize DID object to a file.
	 *
	 * @param out the output file object
	 * @throws DIDSyntaxException  if a serialization error occurs
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #serialize(File)} instead
	 */
	@Deprecated
	public void toJson(File out) throws DIDSyntaxException, IOException {
		serialize(out);
	}
}
