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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonCreator;

/**
 * The credential request class.
 */

public class CredentialRequest extends IDChainRequest<CredentialRequest> {
	private static final Logger log = LoggerFactory.getLogger(CredentialRequest.class);

	private DIDURL id;
	private VerifiableCredential vc;
	private DIDDocument signer;

	@JsonCreator
	protected CredentialRequest() {}

	private CredentialRequest(Operation operation) {
		super(operation);
	}

	protected CredentialRequest(CredentialRequest request) {
		super(request);
		this.id = request.id;
		this.vc = request.vc;
		this.signer = request.signer;
	}

	/**
	 * Constructs the 'declare' credential Request.
	 *
	 * @param vc the VerifiableCredential object needs to be declare
	 * @param signer the credential owner's DIDDocument object
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public static CredentialRequest declare(VerifiableCredential vc,
			DIDDocument signer, DIDURL signKey, String storepass)
			throws DIDStoreException, InvalidKeyException {
		CredentialRequest request = new CredentialRequest(Operation.DECLARE);
		request.setPayload(vc);
		request.setSigner(signer);
		try {
			request.seal(signer, signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			// should never happen
			log.error("INTERNAL - Seal the credential request", ignore);
			return null;
		}

		return request;
	}

	/**
	 * Constructs the 'revoke' credential Request.
	 *
	 * @param vc the VerifiableCredential object needs to be revoke
	 * @param doc the credential owner's or issuer's DIDDocument object
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public static CredentialRequest revoke(VerifiableCredential vc,
			DIDDocument doc, DIDURL signKey, String storepass)
			throws DIDStoreException, InvalidKeyException {
		CredentialRequest request = new CredentialRequest(Operation.REVOKE);
		request.setPayload(vc);
		request.setSigner(doc);
		try {
			request.seal(doc, signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			// should never happen
			log.error("INTERNAL - Seal the credential request", ignore);
			return null;
		}

		return request;
	}

	/**
	 * Constructs the 'revoke' credential Request.
	 *
	 * @param id the id of the VerifiableCredential needs to be revoke
	 * @param doc the credential owner's or issuer's DIDDocument object
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 * @throws InvalidKeyException there is no an authentication key.
	 */
	public static CredentialRequest revoke(DIDURL id, DIDDocument doc,
			DIDURL signKey, String storepass)
			throws DIDStoreException, InvalidKeyException {
		CredentialRequest request = new CredentialRequest(Operation.REVOKE);
		request.setPayload(id);
		request.setSigner(doc);
		try {
			request.seal(doc, signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			// should never happen
			log.error("INTERNAL - Seal the credential request", ignore);
			return null;
		}

		return request;
	}

	private void setSigner(DIDDocument initiator) {
		this.signer = initiator;
	}

	public DIDURL getCredentialId() {
		return id;
	}

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

	@Override
	protected void sanitize(boolean withProof) throws MalformedIDChainRequestException {
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

		if (withProof) {
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
	}

	public void seal(DIDDocument doc, DIDURL signKey, String storepass)
			throws MalformedIDChainRequestException, DIDStoreException, InvalidKeyException {
		if (!doc.isAuthenticationKey(signKey))
			throw new InvalidKeyException("Not an authentication key.");

		sanitize(false);

		String signature = doc.sign(signKey, storepass, getSigningInputs());
		setProof(new Proof(signKey, signature));
	}

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
