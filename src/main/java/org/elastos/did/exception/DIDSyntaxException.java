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

import org.elastos.did.DIDDocument;
import org.elastos.did.TransferTicket;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.VerifiablePresentation;

/**
 * Thrown to indicate that the DID syntax has error.
 */
public class DIDSyntaxException extends DIDException {
	private static final long serialVersionUID = 554093083783734303L;

	/**
	 * Constructs the DIDSyntaxException.
	 */
	public DIDSyntaxException() {
        super();
    }

	/**
	 * Constructs the DIDSyntaxException with the given message.
	 *
	 * @param message the message string
	 */
    public DIDSyntaxException(String message) {
        super(message);
    }

    /**
     * Constructs the DIDSyntaxException with the given message and the reason.
     *
     * @param message the message string
     * @param cause the reason
     */
    public DIDSyntaxException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs the DIDSyntaxException with the given reason.
     *
     * @param cause the reason
     */
    public DIDSyntaxException(Throwable cause) {
        super(cause);
    }

	public static DIDSyntaxException instantiateFor(Class<?> clazz,
			String message, Throwable cause) {
		DIDSyntaxException ex;

		String fqn = clazz.getCanonicalName();
		if (fqn.equals(DIDDocument.class.getCanonicalName()))
			ex = new MalformedDocumentException(message, cause);
		else if (fqn.equals(VerifiableCredential.class.getCanonicalName()))
			ex = new MalformedCredentialException(message, cause);
		else if (fqn.equals(VerifiablePresentation.class.getCanonicalName()))
			ex = new MalformedPresentationException(message, cause);
		else if (fqn.equals(TransferTicket.class.getCanonicalName()))
			ex = new MalformedTransferTicketException(message, cause);
		else if (fqn.endsWith("Metadata"))
			ex = new MalformedMetadataException(message, cause);
		else if (fqn.endsWith("IDChainRequest"))
			ex = new MalformedIDChainRequestException(message, cause);
		else if (fqn.endsWith("IDChainTransaction"))
			ex = new MalformedIDChainTransactionException(message, cause);
		else if (fqn.endsWith("ResolveResult"))
			ex = new MalformedResolveResultException(message, cause);
		else if (fqn.endsWith("ResolveRequest"))
			ex = new MalformedResolveRequestException(message, cause);
		else if (fqn.endsWith("ResolveResponse"))
			ex = new MalformedResolveResponseException(message, cause);
		else if (fqn.endsWith("Export"))
			ex = new MalformedExportDataException(message, cause);
		else
			ex = new DIDSyntaxException(message, cause);

		return ex;
	}
}
