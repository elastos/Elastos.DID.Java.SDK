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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Calendar;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import org.elastos.did.Constants;
import org.elastos.did.DID;
import org.elastos.did.DIDAdapter;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDResolver;
import org.elastos.did.DIDURL;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.DIDTransactionException;
import org.elastos.did.exception.MalformedDIDException;
import org.elastos.did.exception.MalformedDIDURLException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DummyBackend implements DIDAdapter, DIDResolver {
	private static final Logger log = LoggerFactory.getLogger(DummyBackend.class);

	private static Random random = new Random();

	private LinkedList<DIDTransaction> idtxs;
	private LinkedList<CredentialTransaction> vctxs;

	public DummyBackend() {
		idtxs = new LinkedList<DIDTransaction>();
		vctxs = new LinkedList<CredentialTransaction>();
	}

	private static String generateTxid() {
        StringBuffer sb = new StringBuffer();
        while(sb.length() < 32){
            sb.append(Integer.toHexString(random.nextInt()));
        }

        return sb.toString();
    }

	public void reset() {
		idtxs.clear();
		vctxs.clear();
	}

	private DIDTransaction getLastDidTransaction(DID did) {
		for (DIDTransaction tx : idtxs) {
			if (tx.getDid().equals(did))
				return tx;
		}

		return null;
	}

	@Override
	public synchronized void createDidTransaction(String payload, String memo)
			throws DIDTransactionException {
		DIDRequest request;
		try {
			request = IDChainRequest.parse(payload, DIDRequest.class);
		} catch (DIDSyntaxException e) {
			throw new DIDTransactionException(e);
		}

		log.info("ID Transaction[{}] - {}", request.getOperation(), request.getDid());
		log.debug("    payload: {}", request.toString(true));

		if (request.getOperation() != IDChainRequest.Operation.DEACTIVATE)
			log.debug("    document: {}", request.getDocument().toString(true));

		try {
			if (!request.isValid())
				throw new DIDTransactionException("Invalid DID transaction request.");
		} catch (DIDResolveException e) {
			log.error("INTERNAL - resolve failed when verify the did transaction", e);
			throw new DIDTransactionException("Resove DID error");
		}

		if (request.getOperation() != IDChainRequest.Operation.DEACTIVATE) {
			if (!request.getDocument().isValid())
				throw new DIDTransactionException("Invalid DID Document.");
		}

		DIDTransaction tx = getLastDidTransaction(request.getDid());
		if (tx != null) {
			if (tx.getRequest().getOperation() == IDChainRequest.Operation.DEACTIVATE)
				throw new DIDTransactionException("DID " + request.getDid() + " already deactivated");
		}

		switch (request.getOperation()) {
		case CREATE:
			if (tx != null)
				throw new DIDTransactionException("DID already exists.");

			break;

		case UPDATE:
			if (tx == null)
				throw new DIDTransactionException("DID not exists.");

			if (!request.getPreviousTxid().equals(tx.getTransactionId()))
				throw new DIDTransactionException("Previous transaction id missmatch.");

			if (tx.getRequest().getDocument().isCustomizedDid()) {
				List<DID> orgControllers = tx.getRequest().getDocument().getControllers();
				List<DID> curControllers = request.getDocument().getControllers();

				if (!curControllers.equals(orgControllers))
					throw new DIDTransactionException("Document controllers changed.");
			}

			break;

		case TRANSFER:
			if (tx == null)
				throw new DIDTransactionException("DID not exists.");

			if (!request.getTransferTicket().isValid())
				throw new DIDTransactionException("Invalid transfer ticket.");

			if (!request.getTransferTicket().getSubject().equals(request.getDid()))
				throw new DIDTransactionException("Ticket subject mismatched with target DID.");

			if (!request.getDocument().hasController(request.getTransferTicket().getTo()))
				throw new DIDTransactionException("Ticket owner not a controller of target DID.");

			boolean hasSignature = false;
			for (DIDDocument.Proof proof : request.getDocument().getProofs()) {
				if (proof.getCreator().getDid().equals(request.getTransferTicket().getTo()))
					hasSignature = true;
			}
			if (!hasSignature)
				throw new DIDTransactionException("New document not include the ticket owner's signature.");

			break;

		case DEACTIVATE:
			if (tx == null)
				throw new DIDTransactionException("DID not exist.");

			break;

		default:
			throw new DIDTransactionException("Invalid opreation.");
		}

		tx = new DIDTransaction(generateTxid(),
				Calendar.getInstance(Constants.UTC).getTime(), request);
		idtxs.add(0, tx);
		log.info("ID Transaction[{}] - {} success", request.getOperation(), request.getDid());
	}

	@Override
	public InputStream resolveDid(String requestId, String did, boolean all)
			throws DIDResolveException {
		log.info("Resolveing DID {} ...", did);

		if (!did.startsWith("did:elastos:"))
			did = "did:elastos:" + did;

		DID target;
		try {
			target = new DID(did);
		} catch (MalformedDIDException e) {
			throw new DIDResolveException("Invalid did", e);
		}

		DIDBiography bio = new DIDBiography(target, DIDBiography.STATUS_NOT_FOUND);
		DIDTransaction last = getLastDidTransaction(target);
		if (last != null) {
			if (last.getOperation().equals(IDChainRequest.Operation.DEACTIVATE.toString())) {
				bio.setStatus(DIDBiography.STATUS_DEACTIVATED);
		    } else {
				if (last.getRequest().getDocument().isExpired())
					bio.setStatus(DIDBiography.STATUS_EXPIRED);
				else
					bio.setStatus(DIDBiography.STATUS_VALID);
			}
		}

		if (bio.getStatus() != DIDBiography.STATUS_NOT_FOUND) {
			for (DIDTransaction tx : idtxs) {
				if (tx.getDid().equals(target)) {
					bio.addTransaction(tx);;

					if (!all)
						break;
				}
			}
		}

		DIDResolveResponse response = new DIDResolveResponse(requestId, bio);
		InputStream os = new ByteArrayInputStream(response.toString(true).getBytes());

		log.info("Resolve DID {} {}", did, bio.getStatus());
		return os;
	}

	private CredentialTransaction getCredentialRevokeTransaction(DIDURL id, DID signer) {
		for (CredentialTransaction tx : vctxs) {
			if (tx.getId().equals(id) &&
					tx.getRequest().getOperation() == IDChainRequest.Operation.REVOKE &&
					tx.getRequest().getProof().getVerificationMethod().getDid().equals(signer))
				return tx;
		}

		return null;
	}

	private CredentialTransaction getCredentialDeclareTransaction(DIDURL id) {
		for (CredentialTransaction tx : vctxs) {
			if (tx.getId().equals(id) &&
					tx.getRequest().getOperation() == IDChainRequest.Operation.DECLARE)
				return tx;
		}

		return null;
	}

	@Override
	public synchronized void createCredentialTransaction(String payload, String memo)
			throws DIDTransactionException {
		CredentialRequest request;
		try {
			request = CredentialRequest.parse(payload, CredentialRequest.class);
		} catch (DIDSyntaxException e) {
			throw new DIDTransactionException(e);
		}

		log.info("VC Transaction[{}] - {} ", request.getOperation(), request.getCredentialId());
		log.debug("    payload: {}", request.toString(true));

		if (request.getOperation() == IDChainRequest.Operation.DECLARE)
			log.debug("    credential: {}", request.getCredential().toString(true));

		try {
			if (!request.isValid())
				throw new DIDTransactionException("Invalid ID transaction request.");
		} catch (DIDResolveException e) {
			log.error("INTERNAL - resolve failed when verify the id transaction", e);
			throw new DIDTransactionException("Resove DID error");
		}

		CredentialTransaction tx;

		switch (request.getOperation()) {
		case DECLARE:
			// Declared already
			tx = getCredentialDeclareTransaction(request.getCredentialId());
			if (tx != null)
				throw new DIDTransactionException("Credential already exists.");

			// Revoked by the controller
			tx = getCredentialRevokeTransaction(request.getCredentialId(),
					request.getCredential().getSubject().getId());
			if (tx != null)
				throw new DIDTransactionException("Credential already revoked by the controller.");

			// Revoked by the issuer
			tx = getCredentialRevokeTransaction(request.getCredentialId(),
					request.getCredential().getIssuer());
			if (tx != null)
				throw new DIDTransactionException("Credential already revoked by the issuer.");

			break;

		case REVOKE:
			tx = getCredentialRevokeTransaction(request.getCredentialId(),
					request.getProof().getVerificationMethod().getDid());
			if (tx != null)
				throw new DIDTransactionException("Same revoke transaction already exists.");

			break;

		default:
			throw new DIDTransactionException("Invalid opreation.");
		}

		tx = new CredentialTransaction(generateTxid(),
				Calendar.getInstance(Constants.UTC).getTime(), request);
		vctxs.add(0, tx);
		log.info("VC Transaction[{}] - {} success", request.getOperation(), request.getCredentialId());
	}

	@Override
	public InputStream resolveCredential(String requestId, String id)
			throws DIDResolveException {
		log.info("Resolveing credential {} ...", id);

		DIDURL target;
		try {
			target = new DIDURL(id);
		} catch (MalformedDIDURLException e) {
			throw new DIDResolveException("Invalid credential id", e);
		}

		CredentialTransaction declareTx = getCredentialDeclareTransaction(target);
		CredentialTransaction revokeTx = null;
		if (declareTx != null)  {
			CredentialTransaction controllerRevokeTx = getCredentialRevokeTransaction(target,
					declareTx.getRequest().getCredential().getSubject().getId());

			CredentialTransaction issuerRevokeTx = getCredentialRevokeTransaction(target,
					declareTx.getRequest().getCredential().getIssuer());

			if (controllerRevokeTx != null && issuerRevokeTx != null) {
				if (issuerRevokeTx.getTimestamp().after(controllerRevokeTx.getTimestamp()))
					revokeTx = controllerRevokeTx;
				else
					revokeTx = issuerRevokeTx;
			} else {
				if (controllerRevokeTx != null)
					revokeTx = controllerRevokeTx;
				else if (issuerRevokeTx != null)
					revokeTx = issuerRevokeTx;
			}
		}

		CredentialBiography bio = new CredentialBiography(target, CredentialBiography.STATUS_NOT_FOUND);
		if (declareTx != null) {
			if (revokeTx != null) {
				bio.setStatus(CredentialBiography.STATUS_REVOKED);
				bio.addTransaction(revokeTx);
			} else {
				if (declareTx.getRequest().getCredential().isExpired())
					bio.setStatus(CredentialBiography.STATUS_EXPIRED);
				else
					bio.setStatus(CredentialBiography.STATUS_VALID);
			}

			bio.addTransaction(declareTx);
		}

		CredentialResolveResponse response = new CredentialResolveResponse(requestId, bio);
		InputStream os = new ByteArrayInputStream(response.toString(true).getBytes());

		log.info("Resolve VC {} {}", id, bio.getStatus());
		return os;
	}

	@Override
	public InputStream listCredentials(String requestId, String did, int skip,
			int limit) throws DIDResolveException {
		if (limit > CredentialList.MAX_SIZE)
			limit = CredentialList.MAX_SIZE;

		log.info("Listing credentials {} {}/{}...", did, skip, limit);

		DID target;
		try {
			target = new DID(did);
		} catch (MalformedDIDException e) {
			throw new DIDResolveException("Invalid did", e);
		}

		CredentialList cl = new CredentialList(target);
		for (CredentialTransaction tx : vctxs) {
			if (tx.getRequest().getCredential().getSubject().getId().equals(target)) {
				if (skip > 0) {
					--skip;
					continue;
				}

				if (limit > 0) {
					--limit;
					cl.addCredentialId(tx.getId());
				} else
					break;
			}
		}

		InputStream os = new ByteArrayInputStream(cl.toString(true).getBytes());
		log.info("List credentials {} total {}", did, cl.size());
		return os;
	}

	@Override
	public InputStream resolveCredentialRevocation(String requestId, String id,
			String signer) throws DIDResolveException {
		log.info("Resolve revocation for {} from {}...", id, signer);

		DIDURL target;
		DID signerDid;
		try {
			target = new DIDURL(id);
			signerDid = new DID(signer);
		} catch (MalformedDIDException e) {
			throw new DIDResolveException("Invalid signer did", e);
		} catch (MalformedDIDURLException e) {
			throw new DIDResolveException("Invalid credential id", e);
		}

		CredentialBiography bio = new CredentialBiography(target, CredentialBiography.STATUS_VALID);
		CredentialTransaction tx = getCredentialRevokeTransaction(target, signerDid);
		if (tx != null) {
			bio.setStatus(CredentialBiography.STATUS_REVOKED);
			bio.addTransaction(tx);
		}

		CredentialResolveResponse response = new CredentialResolveResponse(requestId, bio);
		InputStream os = new ByteArrayInputStream(response.toString(true).getBytes());

		log.info("Resolve revocation {} {}", id, bio.getStatus());
		return os;
	}
}
