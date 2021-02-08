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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Calendar;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicInteger;

import org.elastos.did.Constants;
import org.elastos.did.DID;
import org.elastos.did.DIDAdapter;
import org.elastos.did.DIDDocument;
import org.elastos.did.DIDURL;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDTransactionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

public class SimulatedIDChain {
	// For mini HTTP server
	protected static final String DEFAULT_HOST = "localhost";
	protected static final int DEFAULT_PORT = 9123;

	private String host;
	private int port;
	private HttpServer server;
	private ThreadPoolExecutor executor;

	// For simulate the ID chain
	private static Random random = new Random();
	private ConcurrentLinkedDeque<DIDTransaction> idtxs;
	private ConcurrentLinkedDeque<CredentialTransaction> vctxs;

	private static final Logger log = LoggerFactory.getLogger(SimulatedIDChain.class);

	private SimulatedIDChain(String host, int port) {
		this.host = host;
		this.port = port;

		idtxs = new ConcurrentLinkedDeque<DIDTransaction>();
		vctxs = new ConcurrentLinkedDeque<CredentialTransaction>();
	}

	public SimulatedIDChain(int port) {
		this(DEFAULT_HOST, port);
	}

	public SimulatedIDChain() {
		this(DEFAULT_PORT);
	}

	public void reset() {
		idtxs.clear();
		vctxs.clear();
	}

	private static String generateTxid() {
        StringBuffer sb = new StringBuffer();
        while(sb.length() < 32){
            sb.append(Integer.toHexString(random.nextInt()));
        }

        return sb.toString();
    }

	private DIDTransaction getLastDidTransaction(DID did) {
		for (DIDTransaction tx : idtxs) {
			if (tx.getDid().equals(did))
				return tx;
		}

		return null;
	}

	private DIDDocument getLastDidDocument(DID did) {
		for (DIDTransaction tx : idtxs) {
			if (tx.getDid().equals(did) &&
					tx.getRequest().getOperation() != IDChainRequest.Operation.DEACTIVATE)
				return tx.getRequest().getDocument();
		}

		return null;
	}

	private synchronized void createDidTransaction(DIDRequest request)
			throws DIDTransactionException {
		log.debug("ID Transaction[{}] - {}", request.getOperation(), request.getDid());
		log.trace("    payload: {}", request.toString(true));

		if (request.getOperation() != IDChainRequest.Operation.DEACTIVATE)
			log.trace("    document: {}", request.getDocument().toString(true));

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

			try {
				if (!request.getTransferTicket().isValid())
					throw new DIDTransactionException("Invalid transfer ticket.");
			} catch (DIDResolveException e) {
				throw new DIDTransactionException(e);
			}

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
		idtxs.addFirst(tx);
		log.trace("ID Transaction[{}] - {} success", request.getOperation(), request.getDid());
	}

	private DIDResolveResponse resolveDid(DIDResolveRequest request) {
		log.debug("Resolveing DID {} ...", request.getDid());

		DIDBiography bio = new DIDBiography(request.getDid());
		DIDTransaction last = getLastDidTransaction(request.getDid());
		if (last != null) {
			int limit;
			if (last.getRequest().getOperation() == IDChainRequest.Operation.DEACTIVATE) {
				bio.setStatus(DIDBiography.Status.DEACTIVATED);
				limit = request.isResolveAll() ? -1 : 2;
			} else {
				bio.setStatus(DIDBiography.Status.VALID);
				limit = request.isResolveAll() ? -1 : 1;
			}

			for (DIDTransaction tx : idtxs) {
				if (tx.getDid().equals(request.getDid())) {
					bio.addTransaction(tx);

					if (limit < 0)
						continue;

					if (--limit == 0)
						break;
				}
			}
		} else {
			bio.setStatus(DIDBiography.Status.NOT_FOUND);
		}

		log.trace("Resolve DID {} {}", request.getDid(), bio.getStatus());
		return new DIDResolveResponse(request.getRequestId(), bio);
	}

	private CredentialTransaction getCredentialRevokeTransaction(DIDURL id, DID signer) {
		DIDDocument ownerDoc = getLastDidDocument(id.getDid());
		DIDDocument signerDoc = null;
		if (signer != null && !signer.equals(id.getDid()))
			signerDoc = getLastDidDocument(signer);

		for (CredentialTransaction tx : vctxs) {
			if (tx.getId().equals(id) &&
					tx.getRequest().getOperation() == IDChainRequest.Operation.REVOKE) {
				DID did = tx.getRequest().getProof().getVerificationMethod().getDid();

				if (did.equals(id.getDid())) // controller revoked
					return tx;

				if (signer != null && did.equals(signer)) // issuer revoked
					return tx;

				if (ownerDoc != null && ownerDoc.hasController(did)) // controller revoked
					return tx;

				if (signerDoc != null && signerDoc.hasController(did)) // issuer revoked
					return tx;
			}
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

	private synchronized void createCredentialTransaction(CredentialRequest request)
			throws DIDTransactionException {
		log.debug("VC Transaction[{}] - {} ", request.getOperation(), request.getCredentialId());
		log.trace("    payload: {}", request.toString(true));

		if (request.getOperation() == IDChainRequest.Operation.DECLARE)
			log.trace("    credential: {}", request.getCredential().toString(true));

		try {
			if (!request.isValid())
				throw new DIDTransactionException("Invalid ID transaction request.");
		} catch (DIDResolveException e) {
			log.error("INTERNAL - resolve failed when verify the id transaction", e);
			throw new DIDTransactionException("Resove DID error");
		}

		CredentialTransaction declareTx = getCredentialDeclareTransaction(request.getCredentialId());
		CredentialTransaction revokeTx = null;

		switch (request.getOperation()) {
		case DECLARE:
			if (declareTx != null) // Declared already
				throw new DIDTransactionException("Credential already exists.");

			revokeTx = getCredentialRevokeTransaction(
					request.getCredentialId(), request.getCredential().getIssuer());
			if (revokeTx != null) // Revoked already
				throw new DIDTransactionException("Credential already revoked by "
						+ revokeTx.getRequest().getProof().getVerificationMethod().getDid());

			break;

		case REVOKE:
			DID issuer = declareTx != null ? declareTx.getRequest().getCredential().getIssuer()
					: request.getProof().getVerificationMethod().getDid();

			revokeTx = getCredentialRevokeTransaction(request.getCredentialId(), issuer);
			if (revokeTx != null)
				throw new DIDTransactionException("Credential already revoked by "
						+ revokeTx.getRequest().getProof().getVerificationMethod().getDid());

			break;

		default:
			throw new DIDTransactionException("Invalid opreation.");
		}

		CredentialTransaction tx = new CredentialTransaction(generateTxid(),
				Calendar.getInstance(Constants.UTC).getTime(), request);
		vctxs.addFirst(tx);
		log.trace("VC Transaction[{}] - {} success", request.getOperation(), request.getCredentialId());
	}

	private CredentialResolveResponse resolveCredential(CredentialResolveRequest request) {
		log.debug("Resolveing credential {} ...", request.getId());

		CredentialTransaction declareTx = getCredentialDeclareTransaction(request.getId());

		DID issuer = declareTx != null ? declareTx.getRequest().getCredential().getIssuer()
				: request.getIssuer();
		CredentialTransaction revokeTx = issuer != null ? getCredentialRevokeTransaction(
				request.getId(), issuer) : null;

		CredentialBiography bio = new CredentialBiography(request.getId());
		if (revokeTx != null) {
			bio.setStatus(CredentialBiography.Status.REVOKED);
			bio.addTransaction(revokeTx);
			if (declareTx != null)
				bio.addTransaction(declareTx);
		} else {
			if (declareTx != null) {
				bio.setStatus(CredentialBiography.Status.VALID);
				bio.addTransaction(declareTx);
			} else {
				bio.setStatus(CredentialBiography.Status.NOT_FOUND);
			}
		}

		log.trace("Resolve VC {} {}", request.getId(), bio.getStatus());
		return new CredentialResolveResponse(request.getRequestId(), bio);
	}

	private CredentialListResponse listCredentials(CredentialListRequest request) {
		int skip = request.getSkip();
		int limit = request.getLimit();

		if (skip < 0)
			skip = 0;

		if (limit <= 0)
			limit = CredentialList.DEFAULT_SIZE;
		else if (limit >= CredentialList.MAX_SIZE)
			limit = CredentialList.MAX_SIZE;

		log.debug("Listing credentials {} {}/{}...", request.getDid(), skip, limit);

		CredentialList cl = new CredentialList(request.getDid());
		for (CredentialTransaction tx : vctxs) {
			if (tx.getRequest().getOperation() == IDChainRequest.Operation.REVOKE)
				continue;

			if (tx.getRequest().getCredential().getSubject().getId().equals(request.getDid())) {
				if (skip-- > 0)
					continue;

				if (limit-- > 0)
					cl.addCredentialId(tx.getId());
				else
					break;
			}
		}

		log.trace("List credentials {} total {}", request.getDid(), cl.size());
		return new CredentialListResponse(request.getRequestId(), cl);
	}

	private static class HttpServerThreadFactory implements ThreadFactory {
		private AtomicInteger threadNumber = new AtomicInteger(1);
		private ThreadGroup group;

		public HttpServerThreadFactory() {
			group = Thread.currentThread().getThreadGroup();
		}

		@Override
		public Thread newThread(Runnable r) {
			Thread t = new Thread(group, r,
					"SimulatedIDChain-thread-" + threadNumber.getAndIncrement());

            if (t.isDaemon())
                t.setDaemon(false);
            if (t.getPriority() != Thread.NORM_PRIORITY)
                t.setPriority(Thread.NORM_PRIORITY);

            return t;
		}
	}

	public synchronized void start() throws IOException {
		HttpServer server = HttpServer.create(new InetSocketAddress(host, port), 0);
		ThreadPoolExecutor executor = (ThreadPoolExecutor)Executors.newFixedThreadPool(10);
		executor.setThreadFactory(new HttpServerThreadFactory());
		server.setExecutor(executor);

		server.createContext("/resolve", new  ResolveHandler());
		server.createContext("/idtx", new  IdtxHandler());
		server.start();

		this.server = server;
		this.executor = executor;

		log.info("Simulated IDChain started on {}:{}", host, port);
	}

	public synchronized void stop() {
		if (server == null)
			return;

		server.stop(0);
		executor.shutdown();
		reset();
		server = null;
		log.info("Simulated IDChain stopped");
	}

	public DIDAdapter getAdapter() {
		try {
			return new SimulatedIDChainAdapter(
				new URL("http", host, port, "/resolver"),
				new URL("http", host, port, "/idtx")
			);
		} catch (MalformedURLException ignore) {
			log.error("INTERNAL - error create DIDAdapter", ignore);
			return null;
		}
	}

	private class ResolveHandler implements HttpHandler {
		@Override
		public void handle(HttpExchange exchange) throws IOException {
			if (!exchange.getRequestMethod().equals("POST")) {
				log.error("Invalid resolve request, should use POST method");
				exchange.sendResponseHeaders(400, 0);
				exchange.getResponseBody().close();
				return;
			}

			try {
				ObjectMapper mapper = new ObjectMapper();
				InputStream is = exchange.getRequestBody();
				JsonNode requestJson = mapper.readTree(is);
				JsonNode method = requestJson.get(ResolveRequest.METHOD);
				if (method == null) {
					log.error("Invalid resolve request, missing resolve method");
					exchange.sendResponseHeaders(400, 0);
					exchange.getResponseBody().close();
					return;
				}

				ResolveResponse<?, ?> response;
				switch (method.asText()) {
				case DIDResolveRequest.METHOD_NAME:
					DIDResolveRequest drr = DIDResolveRequest.parse(requestJson, DIDResolveRequest.class);
					response = resolveDid(drr);
					break;

				case CredentialResolveRequest.METHOD_NAME:
					CredentialResolveRequest crr = CredentialResolveRequest.parse(requestJson, CredentialResolveRequest.class);
					response = resolveCredential(crr);
					break;

				case CredentialListRequest.METHOD_NAME:
					CredentialListRequest clr = CredentialListRequest.parse(requestJson, CredentialListRequest.class);
					response = listCredentials(clr);
					break;

				default:
					log.error("Invalid resolve request, unknown resolve method");
					exchange.sendResponseHeaders(400, 0);
					return;
				}

				byte[] json = response.serialize(true).getBytes();
				Headers headers = exchange.getResponseHeaders();
				headers.set("Content-Type", "application/json");
				exchange.sendResponseHeaders(200, json.length);
				OutputStream os = exchange.getResponseBody();
				os.write(json);
				os.close();
			} catch (Exception e) {
				log.error("Error handling the resolve request", e);
				throw new IOException("HTTP Handle error", e);
			}
		}
	}

	private class IdtxHandler implements HttpHandler {
		@Override
		public void handle(HttpExchange exchange) throws IOException {
			if (!exchange.getRequestMethod().equals("POST")) {
				log.error("Invalid ID chain request, should use POST method");
				exchange.sendResponseHeaders(400, 0);
				exchange.getResponseBody().close();
				return;
			}

			try {
				ObjectMapper mapper = new ObjectMapper();
				InputStream is = exchange.getRequestBody();
				JsonNode requestJson = mapper.readTree(is);
				JsonNode header = requestJson.get(IDChainRequest.HEADER);
				if (header == null) {
					log.error("Invalid IDChain request, missing header");
					exchange.sendResponseHeaders(400, 0);
					exchange.getResponseBody().close();
					return;
				}

				JsonNode spec = header.get(IDChainRequest.SPECIFICATION);
				if (spec == null) {
					log.error("Invalid IDChain request, missing specification");
					exchange.sendResponseHeaders(400, 0);
					exchange.getResponseBody().close();
					return;
				}

				switch (spec.asText()) {
				case IDChainRequest.DID_SPECIFICATION:
					DIDRequest dr = DIDRequest.parse(requestJson, DIDRequest.class);
					createDidTransaction(dr);
					break;

				case IDChainRequest.CREDENTIAL_SPECIFICATION:
					CredentialRequest cr = CredentialRequest.parse(requestJson, CredentialRequest.class);
					createCredentialTransaction(cr);
					break;

				default:
					log.error("Invalid resolve request, unknown resolve method");
					exchange.sendResponseHeaders(400, 0);
					return;
				}

				exchange.sendResponseHeaders(202, 0);
				exchange.getResponseBody().close();
			} catch (Exception e) {
				log.error("Error handling the ID chain request", e);
				throw new IOException("HTTP Handle error", e);
			}
		}
	}
}