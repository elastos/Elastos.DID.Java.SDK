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
import org.elastos.did.exception.UnknownInternalException;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonObjectFormatVisitor;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ser.PropertyFilter;
import com.fasterxml.jackson.databind.ser.PropertyWriter;
import com.fasterxml.jackson.databind.ser.impl.SimpleFilterProvider;

/**
 * The abstract super class for all DID entities.
 *
 * <p>
 * This class provides a skeletal implementation for JSON and object mapping,
 * include DIDEntity serialize to JSON and JSON deserialize to DIDEntity
 * objects.
 * </p>
 *
 * @param <T> the type of the class modeled by this DIDEntity object
 */
public abstract class DIDEntity<T> {
	private final static boolean NORMALIZED_DEFAULT = true;

	/**
	 * The default data format.
	 */
	protected final static SimpleDateFormat dateFormat =
			new SimpleDateFormat(Constants.DATE_FORMAT);

	/**
	 * The ISO8601 compatible data format.
	 */
	protected final static SimpleDateFormat isoDateFormat =
			new SimpleDateFormat(Constants.DATE_FORMAT_ISO_8601);

	/**
	 * DID serialization context key name.
	 */
	protected final static String CONTEXT_KEY = "org.elastos.did.context";

	static {
		dateFormat.setTimeZone(Constants.UTC);
		isoDateFormat.setTimeZone(Constants.UTC);
	}

	/**
	 * The DID serialization context class.
	 */
	protected static class SerializeContext {
		private boolean normalized;
		private DID did;

		private SerializeContext() {
			this(false, null);
		}

		private SerializeContext(boolean normalized, DID did) {
			this.normalized = normalized;
			this.did = did;
		}

		/**
		 * Check whether the current serializer working in normalized mode.
		 *
		 * @return true if the serializer working in normalized mode, false otherwise
		 */
		public boolean isNormalized() {
			return normalized;
		}

		/**
		 * Set the current serializer work in normalized mode or not.
		 *
		 * @param normalized true for normalized mode, false otherwise
		 * @return the SerializeContext instance for method chaining
		 */
		public SerializeContext setNormalized(boolean normalized) {
			this.normalized = normalized;
			return this;
		}

		/**
		 * Get the DID object who own the current serialize object.
		 *
		 * @return a DID object
		 */
		public DID getDid() {
			return did;
		}

		/**
		 * Set the DID object who own the current serialize object.
		 *
		 * @param did the owner of the current serialize object
		 * @return the SerializeContext instance for method chaining
		 */
		public SerializeContext setDid(DID did) {
			this.did = did;
			return this;
		}
	}

	/**
	 * DIDPropertyFilter implementation that only uses property name to
	 * determine whether to serialize property as is, or to filter it out.
	 *
	 * <p>
	 * It will include all properties by default. The subclasses could
	 * override the include method to filter the properties.
	 * </p>
	 */
	protected static class DIDPropertyFilter implements PropertyFilter {
		/**
		 * Method called to determine whether property will be included
		 * (if 'true' returned) or filtered out (if 'false' returned).
		 *
		 * @param writer object called to do actual serialization of the field, if not filtered out
		 * @param pojo object that contains property value to serialize
		 * @param context the serialization context object
		 * @return true for include this property, false filtered out
		 */
		protected boolean include(PropertyWriter writer, Object pojo, SerializeContext context) {
				return true;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public void serializeAsField(Object pojo, JsonGenerator gen, SerializerProvider provider,
				PropertyWriter writer) throws Exception {
			SerializeContext context = (SerializeContext)provider.getConfig()
					.getAttributes().getAttribute(DIDEntity.CONTEXT_KEY);

			if (include(writer, pojo, context)) {
				writer.serializeAsField(pojo, gen, provider);
			} else if (!gen.canOmitFields()) { // since 2.3
				writer.serializeAsOmittedField(pojo, gen, provider);
			}
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public void serializeAsElement(Object elementValue, JsonGenerator gen, SerializerProvider provider,
				PropertyWriter writer) throws Exception {
			 writer.serializeAsElement(elementValue, gen, provider);
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		@Deprecated
		public void depositSchemaProperty(PropertyWriter writer, ObjectNode propertiesNode,
				SerializerProvider provider) throws JsonMappingException {
			writer.depositSchemaProperty(propertiesNode, provider);
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public void depositSchemaProperty(PropertyWriter writer, JsonObjectFormatVisitor objectVisitor,
				SerializerProvider provider) throws JsonMappingException {
			writer.depositSchemaProperty(objectVisitor, provider);
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
	}

	/**
	 * Get the ObjectMapper for serialization or deserialization.
	 *
	 * @return a ObjectMapper instance
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
	 * Get the ObjectMapper for serialization with normalized option.
	 *
	 * @param normalized true for normalized output, false otherwise
	 * @return a ObjectMapper instance
	 */
	private ObjectMapper getObjectMapper(boolean normalized) {
		ObjectMapper mapper = getObjectMapper();

		mapper.setConfig(mapper.getSerializationConfig().withAttribute(CONTEXT_KEY,
				new SerializeContext(normalized, getSerializeContextDid())));

		SimpleFilterProvider filters = new SimpleFilterProvider();
		filters.addFilter("publicKeyFilter", DIDDocument.PublicKey.getFilter());
		filters.addFilter("didDocumentProofFilter", DIDDocument.Proof.getFilter());
		filters.addFilter("credentialFilter", VerifiableCredential.getFilter());
		filters.addFilter("credentialProofFilter", VerifiableCredential.Proof.getFilter());
		mapper.setFilterProvider(filters);

		return mapper;
	}

	/**
	 * Convert data that given JSON tree contains into specific DID entity object.
	 *
	 * @param <T> the DID entity type
	 * @param content the JSON node contains the data
	 * @param clazz the class object for the target DID entity
	 * @return the parsed DID entity
	 * @throws DIDSyntaxException if a error occurs when parsing the object
	 */
	protected static<T extends DIDEntity<?>> T parse(JsonNode content, Class<T> clazz)
			throws DIDSyntaxException {
		ObjectMapper mapper = getObjectMapper();

		try {
			T o = mapper.treeToValue(content, clazz);
			o.sanitize();
			return o;
		} catch (JsonProcessingException e) {
			throw DIDSyntaxException.instantiateFor(clazz, e.getMessage(), e);
		}
	}

	/**
	 * Parse a DID entity from a string JSON representation into given
	 * DIDEntity type.
	 *
	 * @param <T> the DID entity type
	 * @param content the string representation of the DID entity
	 * @param clazz the class object for the target DID entity
	 * @return the parsed DID entity
	 * @throws DIDSyntaxException if a error occurs when parsing the object
	 */
	public static<T extends DIDEntity<?>> T parse(String content, Class<T> clazz)
			throws DIDSyntaxException {
		checkArgument(content != null && !content.isEmpty(), "Invalid JSON content");
		checkArgument(clazz != null, "Invalid result class object");

		ObjectMapper mapper = getObjectMapper();

		try {
			T o = mapper.readValue(content, clazz);
			o.sanitize();
			return o;
		} catch (JsonProcessingException e) {
			throw DIDSyntaxException.instantiateFor(clazz, e.getMessage(), e);
		}
	}

	/**
	 * Parse a DID entity from a reader object into given DIDEntity type.
	 *
	 * @param <T> the DID entity type
	 * @param src the reader object to deserialize the object
	 * @param clazz the class object for the target DID entity
	 * @return the parsed DID entity
	 * @throws DIDSyntaxException if a error occurs when parsing the object
	 * @throws IOException if an IO error occurs
	 */
	public static<T extends DIDEntity<?>> T parse(Reader src, Class<T> clazz)
			throws DIDSyntaxException, IOException {
		checkArgument(src != null, "Invalid src reader");
		checkArgument(clazz != null, "Invalid result class object");

		ObjectMapper mapper = getObjectMapper();

		try {
			T o = mapper.readValue(src, clazz);
			o.sanitize();
			return o;
		} catch (JsonParseException | JsonMappingException e) {
			throw DIDSyntaxException.instantiateFor(clazz, e.getMessage(), e);
		}
	}

	/**
	 * Parse a DID entity from an input stream into given DIDEntity type.
	 *
	 * @param <T> the DID entity type
	 * @param src the input stream to deserialize the object
	 * @param clazz the class object for the target DID entity
	 * @return the parsed DID entity
	 * @throws DIDSyntaxException if a error occurs when parsing the object
	 * @throws IOException if an IO error occurs
	 */
	public static<T extends DIDEntity<?>> T parse(InputStream src, Class<T> clazz)
			throws DIDSyntaxException, IOException {
		checkArgument(src != null, "Invalid src input stream");
		checkArgument(clazz != null, "Invalid result class object");

		ObjectMapper mapper = getObjectMapper();

		try {
			T o = mapper.readValue(src, clazz);
			o.sanitize();
			return o;
		} catch (JsonParseException | JsonMappingException e) {
			throw DIDSyntaxException.instantiateFor(clazz, e.getMessage(), e);
		}
	}

	/**
	 * Parse a DID entity from a file into given DIDEntity type.
	 *
	 * @param <T> the DID entity type
	 * @param src the file to deserialize the object
	 * @param clazz the class object for the target DID entity
	 * @return the parsed DID entity
	 * @throws DIDSyntaxException if a error occurs when parsing the object
	 * @throws IOException if an IO error occurs
	 */
	public static<T extends DIDEntity<?>> T parse(File src, Class<T> clazz)
			throws DIDSyntaxException, IOException {
		checkArgument(src != null, "Invalid src file");
		checkArgument(clazz != null, "Invalid result class object");

		ObjectMapper mapper = getObjectMapper();

		try {
			T o = mapper.readValue(src, clazz);
			o.sanitize();
			return o;
		} catch (JsonParseException | JsonMappingException e) {
			throw DIDSyntaxException.instantiateFor(clazz, e.getMessage(), e);
		}
	}

	/**
	 * Serialize this DID entity to a JSON string.
	 *
	 * @param normalized true for normalized output, false otherwise
	 * @return the serialized JSON string
	 */
	public String serialize(boolean normalized) {
		try {
			return getObjectMapper(normalized).writeValueAsString(this);
		} catch (JsonProcessingException e) {
			throw new UnknownInternalException(e);
		}
	}

	/**
	 * Serialize this DID entity to a JSON string in default normalized mode.
	 *
	 * @return the serialized JSON string
	 */
	public String serialize() {
		return serialize(NORMALIZED_DEFAULT);
	}

	/**
	 * Serialize this DID entity to a Writer.
	 *
	 * @param out the output writer object
	 * @param normalized true for normalized output, false otherwise
	 * @throws IOException if an IO error occurs
	 */
	public void serialize(Writer out, boolean normalized) throws IOException {
		checkArgument(out != null, "Invalid out writer");

		try {
			getObjectMapper(normalized).writeValue(out, this);
		} catch (JsonGenerationException | JsonMappingException e) {
			throw new UnknownInternalException(e);
		}
	}

	/**
	 * Serialize DID object to a Writer in default normalized mode.
	 *
	 * @param out the output writer object
	 * @throws IOException if an IO error occurs
	 */
	public void serialize(Writer out) throws IOException {
		serialize(out, NORMALIZED_DEFAULT);
	}

	/**
	 * Serialize DID object to an output stream.
	 *
	 * @param out the output stream object
	 * @param normalized true for normalized output, false otherwise
	 * @throws IOException if an IO error occurs
	 */
	public void serialize(OutputStream out, boolean normalized) throws IOException {
		checkArgument(out != null, "Invalid out stream");

		try {
			getObjectMapper(normalized).writeValue(out, this);
		} catch (JsonGenerationException | JsonMappingException e) {
			throw new UnknownInternalException(e);
		}
	}

	/**
	 * Serialize DID object to an output stream in default normalized mode.
	 *
	 * @param out the output stream object
	 * @throws IOException if an IO error occurs
	 */
	public void serialize(OutputStream out) throws IOException {
		serialize(out, NORMALIZED_DEFAULT);
	}

	/**
	 * Serialize DID object to a file.
	 *
	 * @param out the output file object
	 * @param normalized true for normalized output, false otherwise
	 * @throws IOException if an IO error occurs
	 */
	public void serialize(File out, boolean normalized) throws IOException {
		checkArgument(out != null, "Invalid out file");

		try {
			getObjectMapper(normalized).writeValue(out, this);
		} catch (JsonGenerationException | JsonMappingException e) {
			throw new UnknownInternalException(e);
		}
	}

	/**
	 * Serialize DID object to a file in default normalized mode.
	 *
	 * @param out the output file object
	 * @throws IOException if an IO error occurs
	 */
	public void serialize(File out) throws IOException {
		serialize(out, NORMALIZED_DEFAULT);
	}

	/**
	 * Get the JSON string representation of the object.
	 *
	 * @param normalized true for normalized output, false otherwise
	 * @return a JSON string representation of the object
	 */
	public String toString(boolean normalized) {
		return serialize(normalized);
	}

	/**
	 * Get the JSON string representation of the object in default normalized mode.
	 *
	 * @return a JSON string representation of the object
	 */
	@Override
	public String toString() {
		return toString(NORMALIZED_DEFAULT);
	}

	/**
	 * Serialize this DID entity to a JSON string.
	 *
	 * @param normalized true for normalized output, false otherwise
	 * @return the serialized JSON string
	 * @deprecated use {@link #serialize(boolean)} instead
	 */
	@Deprecated
	public String toJson(boolean normalized) {
		return serialize(normalized);
	}

	/**
	 * Serialize this DID entity to a JSON string in default normalized mode.
	 *
	 * @return the serialized JSON string
	 * @deprecated use {@link #serialize()} instead
	 */
	@Deprecated
	public String toJson() {
		return serialize();
	}

	/**
	 * Serialize this DID entity to a Writer.
	 *
	 * @param out the output writer object
	 * @param normalized true for normalized output, false otherwise
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #serialize(Writer, boolean)} instead
	 */
	@Deprecated
	public void toJson(Writer out, boolean normalized) throws IOException {
		serialize(out, normalized);
	}

	/**
	 * Serialize DID object to a Writer in default normalized mode.
	 *
	 * @param out the output writer object
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #serialize(Writer)} instead
	 */
	@Deprecated
	public void toJson(Writer out) throws IOException {
		serialize(out);
	}

	/**
	 * Serialize DID object to an output stream.
	 *
	 * @param out the output stream object
	 * @param normalized true for normalized output, false otherwise
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #serialize(OutputStream, boolean)} instead
	 */
	@Deprecated
	public void toJson(OutputStream out, boolean normalized) throws IOException {
		serialize(out, normalized);
	}

	/**
	 * Serialize DID object to an output stream in default normalized mode.
	 *
	 * @param out the output stream object
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #serialize(OutputStream)} instead
	 */
	@Deprecated
	public void toJson(OutputStream out) throws IOException {
		serialize(out);
	}

	/**
	 * Serialize DID object to a file.
	 *
	 * @param out the output file object
	 * @param normalized true for normalized output, false otherwise
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #serialize(File, boolean)} instead
	 */
	@Deprecated
	public void toJson(File out, boolean normalized) throws IOException {
		serialize(out, normalized);
	}

	/**
	 * Serialize DID object to a file in default normalized mode.
	 *
	 * @param out the output file object
	 * @throws IOException if an IO error occurs
	 * @deprecated use {@link #serialize(File)} instead
	 */
	@Deprecated
	public void toJson(File out) throws IOException {
		serialize(out);
	}
}
