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

import org.elastos.did.DID;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDURL;
import org.elastos.did.TransferTicket;
import org.elastos.did.crypto.Base64;
import org.elastos.did.exception.DIDException;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDStoreException;
import org.elastos.did.exception.InvalidKeyException;
import org.elastos.did.exception.MalformedIDChainRequestException;
import org.elastos.did.exception.UnknownInternalException;

import com.fasterxml.jackson.annotation.JsonCreator;

/**
 * The DID request class.
 */
public class DIDRequest extends IDChainRequest<DIDRequest> {
	private DID did;
	private DIDDocument doc;

	@JsonCreator
	protected DIDRequest() {}

	private DIDRequest(Operation operation) {
		super(operation);
	}

	private DIDRequest(Operation operation, String previousTxid) {
		super(operation, previousTxid);
	}

	private DIDRequest(Operation operation, TransferTicket ticket) {
		super(operation, ticket);
	}

	protected DIDRequest(DIDRequest request) {
		super(request);
		this.did = request.did;
		this.doc = request.doc;
	}

	/**
	 * Constructs the 'create' DID Request.
	 *
	 * @param doc the DID Document be packed into Request
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 */
	public static DIDRequest create(DIDDocument doc, DIDURL signKey,
			String storepass) throws DIDStoreException {
		DIDRequest request = new DIDRequest(Operation.CREATE);
		request.setPayload(doc);
		try {
			request.seal(signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			throw new UnknownInternalException(ignore);
		}

		return request;
	}

	/**
	 * Constructs the 'update' DID Request.
	 *
	 * @param doc the DID Document be packed into Request
	 * @param previousTxid the previous transaction id string
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 */
	public static DIDRequest update(DIDDocument doc, String previousTxid,
			DIDURL signKey, String storepass) throws DIDStoreException {
		DIDRequest request = new DIDRequest(Operation.UPDATE, previousTxid);
		request.setPayload(doc);
		try {
			request.seal(signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			throw new UnknownInternalException(ignore);
		}

		return request;
	}

	/**
	 * Constructs the 'transfer' DID Request.
	 *
	 * @param doc target DID document
	 * @param ticket the transfer ticket object
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 */
	public static DIDRequest transfer(DIDDocument doc, TransferTicket ticket,
			DIDURL signKey, String storepass) throws DIDStoreException {
		DIDRequest request = new DIDRequest(Operation.TRANSFER, ticket);
		request.setPayload(doc);
		try {
			request.seal(signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			throw new UnknownInternalException(ignore);
		}

		return request;
	}


	/**
	 * Constructs the 'deactivate' DID Request.
	 *
	 * @param doc the DID Document be packed into Request
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach.
	 */
	public static DIDRequest deactivate(DIDDocument doc, DIDURL signKey,
			String storepass) throws DIDStoreException {
		DIDRequest request = new DIDRequest(Operation.DEACTIVATE);
		request.setPayload(doc);
		try {
			request.seal(signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			throw new UnknownInternalException(ignore);
		}

		return request;
	}

	/**
	 * Constructs the 'deactivate' DID Request.
	 *
	 * @param target the DID to be deactivated
	 * @param targetSignKey the target DID's key to sign
	 * @param doc the authorizer's document
	 * @param signKey the key to sign Request
	 * @param storepass the password for DIDStore
	 * @return the IDChainRequest object
	 * @throws DIDStoreException there is no store to attach
	 */
	public static DIDRequest deactivate(DIDDocument target, DIDURL targetSignKey,
			DIDDocument doc, DIDURL signKey, String storepass) throws DIDStoreException {
		DIDRequest request = new DIDRequest(Operation.DEACTIVATE);
		request.setPayload(target);
		try {
			request.seal(targetSignKey, doc, signKey, storepass);
		} catch (MalformedIDChainRequestException ignore) {
			throw new UnknownInternalException(ignore);
		}

		return request;
	}

	/**
	 * Get previous transaction id string.
	 *
	 * @return the transaction id string
	 */
	public String getPreviousTxid() {
		return getHeader().getPreviousTxid();
	}

	/**
	 * Get transfer ticket object.
	 *
	 * @return the TransferTicket object
	 */
	public TransferTicket getTransferTicket() {
		return getHeader().getTransferTicket();
	}

	/**
	 * Get target DID of DID Request.
	 *
	 * @return the DID object
	 */
	public DID getDid() {
		return did;
	}

	/**
	 * Get DID Document of DID Request.
	 *
	 * @return the DIDDocument object
	 */
	public DIDDocument getDocument() {
		return doc;
	}

	private void setPayload(DIDDocument doc) {
		this.did = doc.getSubject();
		this.doc = doc;

		if (getHeader().getOperation() != Operation.DEACTIVATE) {
			String json = doc.toString(true);

			setPayload(Base64.encodeToString(json.getBytes(),
					Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP));
		} else {
			setPayload(doc.getSubject().toString());
		}
	}

	@Override
	protected void sanitize() throws MalformedIDChainRequestException {
		Header header = getHeader();

		if (header == null)
			throw new MalformedIDChainRequestException("Missing header");

		if (header.getSpecification() == null)
			throw new MalformedIDChainRequestException("Missing specification");

		if (!header.getSpecification().equals(DID_SPECIFICATION))
			throw new MalformedIDChainRequestException("Unsupported specification");

		switch (header.getOperation()) {
		case CREATE:
			break;

		case UPDATE:
			if (header.getPreviousTxid() == null || header.getPreviousTxid().isEmpty())
				throw new MalformedIDChainRequestException("Missing previousTxid");
			break;

		case TRANSFER:
			if (header.getTicket() == null || header.getTicket().isEmpty())
				throw new MalformedIDChainRequestException("Missing ticket");
			break;

		case DEACTIVATE:
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
			if (header.getOperation() != Operation.DEACTIVATE) {
				String json = new String(Base64.decode(payload,
						Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP));

				doc = DIDDocument.parse(json);
				did = doc.getSubject();
			} else {
				did = new DID(payload);
			}
		} catch (DIDException e) {
			throw new MalformedIDChainRequestException("Invalid payload", e);
		}

		proof.qualifyVerificationMethod(did);
	}

	private void seal(DIDURL signKey, String storepass)
			throws MalformedIDChainRequestException, DIDStoreException {
		if (!doc.isAuthenticationKey(signKey))
			throw new InvalidKeyException("Not an authentication key.");

		if (getPayload() == null || getPayload().isEmpty())
			throw new MalformedIDChainRequestException("Missing payload");

		String signature = doc.sign(signKey, storepass, getSigningInputs());
		setProof(new Proof(signKey, signature));
	}

	private void seal(DIDURL targetSignKey, DIDDocument doc,
			DIDURL signKey, String storepass)
			throws MalformedIDChainRequestException, DIDStoreException {
		if (!this.doc.isAuthorizationKey(targetSignKey))
			throw new InvalidKeyException("Not an authorization key: " + targetSignKey);

		if (!doc.isAuthenticationKey(signKey))
			throw new InvalidKeyException("Not an authentication key: " + signKey);

		if (getPayload() == null || getPayload().isEmpty())
			throw new MalformedIDChainRequestException("Missing payload");

		String signature = doc.sign(signKey, storepass, getSigningInputs());
		setProof(new Proof(targetSignKey, signature));
	}

	@Override
	protected DIDDocument getSignerDocument() throws DIDResolveException {
		if (doc == null)
			doc = did.resolve();

		return doc;
	}
}
