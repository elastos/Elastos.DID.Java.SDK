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

package org.elastos.did.backend;

import org.elastos.did.DIDDocument;
import org.elastos.did.DIDURL;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.crypto.Base64;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.MalformedIDChainRequestException;
import org.elastos.did.exception.UnknownInternalException;

import com.fasterxml.jackson.annotation.JsonCreator;

/**
 * The credential related chain request class for credential publishing.
 */
public class CredentialRequest extends IDChainRequest<CredentialRequest> {
	private DIDURL id;
	private VerifiableCredential vc;
	private DIDDocument signer;

	/**
	 * Default constructor.
	 */
	@JsonCreator
	protected CredentialRequest() {}

	private CredentialRequest(Operation operation) {
		super(operation);
	}

	/**
	 * Copy constructor.
	 *
	 * @param request another credential request object
	 */
	protected CredentialRequest(CredentialRequest request) {
		super(request);
		this.id = request.id;
		this.vc = request.vc;
		this.signer = request.signer;
	}

	/**
	 * Constructs a credential 'declare' request.
	 *
	 * @param vc the VerifiableCredential object that needs to be declare
	 * @param signer the credential owner's DIDDocument object
	 * @param signKey the key id to sign request
	 * @param storepass the password for private key access from the DID store
	 * @return a CredentialRequest object
	 * @throws DIDStoreException if an error occurred when access the private key
	 */
	public static CredentialRequest declare(VerifiableCredential vc,
			DIDDocument signer, DIDURL signKey, String storepass)
			throws DIDStoreException {
		CredentialRequest request = new CredentialRequest(Operation.DECLARE);
		request.setPayload(vc);
		request.setSigner(signer);
		try {
			request.seal(signer, signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			throw new UnknownInternalException(ignore);
		}

		return request;
	}

	/**
	 * Constructs a credential 'revoke' request.
	 *
	 * @param vc the VerifiableCredential object that needs to be revoke
	 * @param signer the credential owner's DIDDocument object
	 * @param signKey the key id to sign request
	 * @param storepass the password for private key access from the DID store
	 * @return a CredentialRequest object
	 * @throws DIDStoreException if an error occurred when access the private key
	 */
	public static CredentialRequest revoke(VerifiableCredential vc,
			DIDDocument signer, DIDURL signKey, String storepass)
			throws DIDStoreException {
		CredentialRequest request = new CredentialRequest(Operation.REVOKE);
		request.setPayload(vc);
		request.setSigner(signer);
		try {
			request.seal(signer, signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			throw new UnknownInternalException(ignore);
		}

		return request;
	}

	/**
	 * Constructs a credential 'revoke' request.
	 *
	 * @param id the id of the credential that needs to be revoke
	 * @param signer the credential owner's DIDDocument object
	 * @param signKey the key id to sign request
	 * @param storepass the password for private key access from the DID store
	 * @return a CredentialRequest object
	 * @throws DIDStoreException if an error occurred when access the private key
	 */
	public static CredentialRequest revoke(DIDURL id, DIDDocument signer,
			DIDURL signKey, String storepass) throws DIDStoreException {
		CredentialRequest request = new CredentialRequest(Operation.REVOKE);
		request.setPayload(id);
		request.setSigner(signer);
		try {
			request.seal(signer, signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			throw new UnknownInternalException(ignore);
		}

		return request;
	}

	private void setSigner(DIDDocument initiator) {
		this.signer = initiator;
	}

	/**
	 * Get target credential id of this request.
	 *
	 * @return the credential id
	 */
	public DIDURL getCredentialId() {
		return id;
	}

	/**
	 * Get the target VerifiableCredential object of this request.
	 *
	 * @return the VerifiableCredential object
	 */
	public VerifiableCredential getCredential() {
		return vc;
	}

	private void setPayload(VerifiableCredential vc) {
		this.id = vc.getId();
		this.vc = vc;

		if (getHeader().getOperation() == Operation.DECLARE) {
			String json = vc.toString(true);

			setPayload(Base64.encodeToString(json.getBytes(),
					Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP));
		} else if (getHeader().getOperation() == Operation.REVOKE) {
			setPayload(vc.getId().toString());
		}
	}

	private void setPayload(DIDURL id) {
		this.id = id;
		this.vc = null;

		setPayload(id.toString());
	}

	/**
	 * Check the validity of the object and normalize the object after
	 * deserialized the CredentialRequest object from JSON.
	 *
	 * @throws MalformedIDChainRequestException if the object is invalid
	 */
	@Override
	protected void sanitize() throws MalformedIDChainRequestException {
		Header header = getHeader();

		if (header == null)
			throw new MalformedIDChainRequestException("Missing header");

		if (header.getSpecification() == null)
			throw new MalformedIDChainRequestException("Missing specification");

		if (!header.getSpecification().equals(CREDENTIAL_SPECIFICATION))
			throw new MalformedIDChainRequestException("Unsupported specification");

		switch (header.getOperation()) {
		case DECLARE:
		case REVOKE:
			break;

		default:
			throw new MalformedIDChainRequestException("Invalid operation " + header.getOperation());
		}

		String payload = getPayload();
		if (payload == null || payload.isEmpty())
			throw new MalformedIDChainRequestException("Missing payload");

		Proof proof = getProof();
		if (proof == null)
			throw new MalformedIDChainRequestException("Missing proof");

		try {
			if (header.getOperation() == Operation.DECLARE) {
				String json = new String(Base64.decode(payload,
						Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP));

				vc = VerifiableCredential.parse(json);
				id = vc.getId();
			} else {
				id = new DIDURL(payload);
			}
		} catch (DIDException e) {
			throw new MalformedIDChainRequestException("Invalid payload", e);
		}

		proof.qualifyVerificationMethod(id.getDid());
	}

	private void seal(DIDDocument doc, DIDURL signKey, String storepass)
			throws MalformedIDChainRequestException, DIDStoreException {
		if (!doc.isAuthenticationKey(signKey))
			throw new InvalidKeyException("Not an authentication key.");

		if (getPayload() == null || getPayload().isEmpty())
			throw new MalformedIDChainRequestException("Missing payload");

		String signature = doc.sign(signKey, storepass, getSigningInputs());
		setProof(new Proof(signKey, signature));
	}

	/**
	 * Get the DIDDocument of the request signer.
	 *
	 * @return the signer's DIDDocument object
	 * @throws DIDResolveException if error occurred when resolving
	 * 		   DID document
	 */
	@Override
	protected DIDDocument getSignerDocument() throws DIDResolveException {
		if (signer != null)
			return signer;

		if (getOperation() == Operation.DECLARE)
			signer = getCredential().getSubject().getId().resolve();
		else {
			if (getCredential() != null)
				signer = getCredential().getSubject().getId().resolve();
			else
				signer = getProof().getVerificationMethod().getDid().resolve();
		}

		return signer;
	}

}
