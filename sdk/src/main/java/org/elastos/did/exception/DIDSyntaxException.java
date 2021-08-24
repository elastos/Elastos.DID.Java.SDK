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

package org.elastos.did.exception;

/**
 * DIDException is the superclass of all DID JSON syntax exceptions.
 */
public class DIDSyntaxException extends DIDException {
	private static final long serialVersionUID = 554093083783734303L;

	/**
	 * Constructs a DIDSyntaxException with null as its error detail message.
	 */
	public DIDSyntaxException() {
		super();
	}

	/**
	 * Constructs a DIDSyntaxException with the specified detail message.
	 *
	 * @param message The detail message
	 */
	public DIDSyntaxException(String message) {
		super(message);
	}

	/**
	 * Constructs a DIDSyntaxException with the specified detail
	 * message and cause.
	 *
	 * Note that the detail message associated with cause is not automatically
	 * incorporated into this exception's detail message.
	 *
	 * @param message The detail message
	 * @param cause The cause. A null value is permitted, and indicates
	 * 			that the cause is nonexistent or unknown
	 */
	public DIDSyntaxException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Constructs a DIDSyntaxException with the specified cause and
	 * a detail message from that cause.
	 *
	 * @param cause The cause. A null value is permitted, and indicates
	 * 			that the cause is nonexistent or unknown
	 */
	public DIDSyntaxException(Throwable cause) {
		super(cause);
	}

	/**
	 * Helper method for the generic DID entity parser to create exceptions
	 * for specified purposes.
	 *
	 * @param clazz The class object of DID entity
	 * @param message The detail message
	 * @param cause The cause
	 * @return The specific exception object for the DID entity.
	 */
	public static DIDSyntaxException instantiateFor(Class<?> clazz,
			String message, Throwable cause) {
		DIDSyntaxException ex;

		switch (clazz.getSimpleName()) {
		case "DIDDocument":
			ex = new MalformedDocumentException(message, cause);
			break;

		case "VerifiableCredential":
			ex = new MalformedCredentialException(message, cause);
			break;

		case "VerifiablePresentation":
			ex = new MalformedPresentationException(message, cause);
			break;

		case "TransferTicket":
			ex = new MalformedTransferTicketException(message, cause);
			break;

		case "DIDMetadata":
		case "CredentialMetadata":
			ex = new MalformedMetadataException(message, cause);
			break;

		case "DIDRequest":
		case "CredentialRequest":
			ex = new MalformedIDChainRequestException(message, cause);
			break;

		case "DIDTransaction":
		case "CredentialTransaction":
			ex = new MalformedIDChainTransactionException(message, cause);
			break;

		case "DIDBiography":
		case "CredentialBiography":
		case "CredentialList":
			ex = new MalformedResolveResultException(message, cause);
			break;

		case "DIDResolveRequest":
		case "CredentialResolveRequest":
		case "CredentialListRequest":
			ex = new MalformedResolveRequestException(message, cause);
			break;

		case "DIDResolveResponse":
		case "CredentialResolveResponse":
		case "CredentialListResponse":
			ex = new MalformedResolveResponseException(message, cause);
			break;

		case "DIDExport":
		case "RootIdentityExport":
			ex = new MalformedExportDataException(message, cause);
			break;

		default:
			ex = new DIDSyntaxException(message, cause);
		}

		return ex;
	}
}
