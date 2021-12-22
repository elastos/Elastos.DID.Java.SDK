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

import static com.google.common.base.Preconditions.checkArgument;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import org.elastos.did.VerifiableCredential;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.exception.DIDTransactionException;
import org.elastos.did.exception.UnknownInternalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

/**
 * Simulated ID chain for developing and testing DID SDK and applications.
 *
 * <p>
 * All behaviors are implement according the <a href="https://github.com/elastos/Elastos.DID.Method/">
 * Elastos DID method specification</a>.
 * </p>
 *
 * <strong>Create ID transaction</strong>
 * <p>
 * <b>Endpoint</b>: /idtx<br>
 * <b>Method</b>: POST<br>
 * <b>Content-Type</b>: application/json<br>
 * <b>Request Body</b>: Any ID Chain request payload, include DID and VerifiableCredential operations.<br>
 * <b>Response Body</b>: None<br>
 * <b>Success Status</b>: 202<br>
 * </p>
 *
 * <strong>Resolve</strong>
 * <p>
 * <b>Endpoint</b>: /resolve<br>
 * <b>Method</b>: POST<br>
 * <b>Content-Type</b>: application/json<br>
 * <b>Request Body</b>: Any DID or VC resolve/list request.<br>
 * <b>Response Body</b>: Resolved result.<br>
 * <b>Success Status</b>: 200<br>
 * </p>
 *
 * <strong>Reset test data</strong>
 * <p>
 * <b>Endpoint</b>: /reset<br>
 * <b>Parameters</b>(optional): idtxsonly, vctxsonly<br>
 * <b>Method</b>: POST<br>
 * <b>Request Body</b>: None<br>
 * <b>Response Body</b>: None<br>
 * <b>Success Status</b>: 200<br>
 * </p>
 *
 * <strong>Shutdown the simulated ID chain</strong>
 * <p>
 * <b>Endpoint</b>: /shutdown<br>
 * <b>Method</b>: POST<br>
 * <b>Request Body</b>: None<br>
 * <b>Response Body</b>: None<br>
 * <b>Success Status</b>: 202<br>
 * </p>
 *
 * <strong>Command line to start the simulated ID chain</strong>
 * <pre>
 * $ java -jar did.jar simchain --help
 * Usage: org.elastos.did.util.Main simchain [-ehV] [-i=&lt;host&gt;] [-p=&lt;port&gt;]
 * Simulated ID Chain for testing.
 *   -i, --interface=&lt;host&gt;   Server interface, default: localhost
 *   -p, --port=&lt;port&gt;        Server port, default 9123.
 *   -e, --verbase            Verbose error output, default false.
 *   -h, --help               Show this help message and exit.
 *   -V, --version            Print version information and exit.
 * </pre>
 */
public class SimulatedIDChain {
	/**
	 * Default listen host for the HTTP server.
	 */
	public static final String DEFAULT_HOST = "localhost";
	/**
	 * Default listen port for the HTTP server.
	 */
	public static final int DEFAULT_PORT = 9123;

	private String host;
	private int port;
	private HttpServer server;
	private ThreadPoolExecutor executor;

	// For simulate the ID chain
	private static Random random = new Random();
	private ConcurrentLinkedDeque<DIDTransaction> idtxs;
	private ConcurrentLinkedDeque<CredentialTransaction> vctxs;

	private SimulatedIDChainAdapter adapter;

	private Statistics stat;

	private static final Logger log = LoggerFactory.getLogger(SimulatedIDChain.class);

	/**
	 * Create a SimulatedIDChain instance at host:port.
	 *
	 * @param host the HTTP server host
	 * @param port the HTTP server port
	 */
	public SimulatedIDChain(String host, int port) {
		checkArgument(host != null && !host.isEmpty(), "Invalid host");
		checkArgument(port > 0, "Invalid port");

		this.host = host;
		this.port = port;

		idtxs = new ConcurrentLinkedDeque<DIDTransaction>();
		vctxs = new ConcurrentLinkedDeque<CredentialTransaction>();

		stat = new Statistics();
	}

	/**
	 * Create a SimulatedIDChain instance at <b>localhost</b>:port.
	 *
	 * @param port the HTTP server port
	 */
	public SimulatedIDChain(int port) {
		this(DEFAULT_HOST, port);
	}

	/**
	 * Create a SimulatedIDChain instance at the default endpoint
	 * <b>localhost:9123</b>.
	 */
	public SimulatedIDChain() {
		this(DEFAULT_PORT);
	}

	/**
	 * Reset the simulated ID chain to the initial clean state.
	 *
	 * <p>
	 * After reset, all data include the existing DID and credential
	 * transactions will be removed.
	 * </p>
	 */
	public void reset() {
		idtxs.clear();
		vctxs.clear();
		log.info("All transactions reseted.");
	}

	/**
	 * Reset all ID transactions on the simulated ID chain.
	 *
	 * <p>
	 * After reset, all ID transactions will be removed. This may cause the
	 * existing credential transactions can not be verified.
	 * </p>
	 */
	public void resetIdtxs() {
		idtxs.clear();
		log.info("All id transactions reseted.");
	}

	/**
	 * Reset all credential transactions on the simulated ID chain.
	 *
	 * <p>
	 * After reset, all credential transactions will be removed.
	 * </p>
	 */
	public void resetVctxs() {
		vctxs.clear();
		log.info("All credential transactions reseted.");
	}

	private static String generateTxid() {
		byte[] bin = new byte[16];
		random.nextBytes(bin);
		return Hex.toHexString(bin);
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
			if (!request.isValid()) {
				stat.invalidDidRequest();
				throw new DIDTransactionException("Invalid DID transaction request.");
			}
		} catch (DIDResolveException e) {
			stat.invalidDidRequest();
			log.error("INTERNAL - resolve failed when verify the did transaction", e);
			throw new DIDTransactionException("Resove DID error");
		}

		if (request.getOperation() != IDChainRequest.Operation.DEACTIVATE) {
			if (!request.getDocument().isValid()) {
				stat.invalidDidRequestWithInvalidDocument();
				throw new DIDTransactionException("Invalid DID Document.");
			}
		}

		DIDTransaction tx = getLastDidTransaction(request.getDid());
		if (tx != null) {
			if (tx.getRequest().getOperation() == IDChainRequest.Operation.DEACTIVATE) {
				stat.invalidDidRequestOnDeactivatedDid();
				throw new DIDTransactionException("DID " + request.getDid() + " already deactivated");
			}
		}

		switch (request.getOperation()) {
		case CREATE:
			stat.createDid();

			if (tx != null) {
				stat.createDidAlreadyExists();
				throw new DIDTransactionException("DID already exists.");
			}

			if (request.getDocument().isCustomizedDid()) {
				stat.createCustomizedDid();

				if (request.getDocument().getControllerCount() == 1)
					stat.createCustomizedDidWithSingleController();
				else
					stat.createCustomizedDidWithMultiController();

				if (request.getDocument().getMultiSignature() != null)
					stat.createCustomizedDidWithMultisig();
				else
					stat.createCustomizedDidWithSinglesig();
			}

			break;

		case UPDATE:
			stat.updateDid();

			if (tx == null) {
				stat.updateDidNotExists();
				throw new DIDTransactionException("DID not exists.");
			}

			if (request.getDocument().isCustomizedDid()) {
				stat.updateCustomizedDid();

				if (request.getDocument().getControllerCount() == 1)
					stat.updateCustomizedDidWithSingleController();
				else
					stat.updateCustomizedDidWithMultiController();

				if (request.getDocument().getMultiSignature() != null)
					stat.updateCustomizedDidWithMultisig();
				else
					stat.updateCustomizedDidWithSinglesig();
			}

			if (!request.getPreviousTxid().equals(tx.getTransactionId())) {
				stat.updateDidWithWrongTxid();
				throw new DIDTransactionException("Previous transaction id missmatch.");
			}

			if (tx.getRequest().getDocument().isCustomizedDid()) {
				List<DID> orgControllers = tx.getRequest().getDocument().getControllers();
				List<DID> curControllers = request.getDocument().getControllers();

				if (!curControllers.equals(orgControllers)) {
					stat.updateCustomizedDidWithControllersChanged();
					throw new DIDTransactionException("Document controllers changed.");
				}
			}

			break;

		case TRANSFER:
			stat.transferDid();

			if (tx == null) {
				stat.transferDidNotExists();
				throw new DIDTransactionException("DID not exists.");
			}

			try {
				if (!request.getTransferTicket().isValid()) {
					stat.transferDidWithInvalidTicket();
					throw new DIDTransactionException("Invalid transfer ticket.");
				}
			} catch (DIDResolveException e) {
				throw new DIDTransactionException(e);
			}

			if (!request.getTransferTicket().getSubject().equals(request.getDid())) {
				stat.transferDidWithInvalidTicketId();
				throw new DIDTransactionException("Ticket subject mismatched with target DID.");
			}

			if (!request.getDocument().hasController(request.getTransferTicket().getTo())) {
				stat.transferDidWithInvalidTicketTo();
				throw new DIDTransactionException("Ticket owner not a controller of target DID.");
			}

			boolean hasSignature = false;
			for (DIDDocument.Proof proof : request.getDocument().getProofs()) {
				if (proof.getCreator().getDid().equals(request.getTransferTicket().getTo()))
					hasSignature = true;
			}
			if (!hasSignature) {
				stat.transferDidWithInvalidController();
				throw new DIDTransactionException("New document not include the ticket owner's signature.");
			}

			break;

		case DEACTIVATE:
			stat.deactivateDid();

			if (tx == null) {
				stat.deactivateDidNotExists();
				throw new DIDTransactionException("DID not exist.");
			}

			if (tx.getRequest().getDocument().isAuthorizationKey(request.getProof().getVerificationMethod()))
				stat.deactivateDidByAuthroization();
			else
				stat.deactivateDidByOwner();

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

		stat.resolveDid();
		if (request.isResolveAll())
			stat.resolveDidWithAll();
		else
			stat.resolveDidNonAll();

		DIDBiography bio = new DIDBiography(request.getDid());
		DIDTransaction last = getLastDidTransaction(request.getDid());
		if (last != null) {
			int limit;
			if (last.getRequest().getOperation() == IDChainRequest.Operation.DEACTIVATE) {
				stat.resolveDeactivatedDid();
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
			stat.resolveNonExistsDid();
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

		CredentialTransaction controllerTx = null;
		CredentialTransaction issuerTx = null;

		for (CredentialTransaction tx : vctxs) {
			if (tx.getId().equals(id) &&
					tx.getRequest().getOperation() == IDChainRequest.Operation.REVOKE) {
				DID did = tx.getRequest().getProof().getVerificationMethod().getDid();

				if (did.equals(id.getDid()) ||
						(ownerDoc != null && ownerDoc.hasController(did))) { // controller revoked
					if (issuerTx != null)
						return tx;

					controllerTx = tx;
				}

				if ((signer != null && did.equals(signer)) ||
						(signerDoc != null && signerDoc.hasController(did))) { // issuer revoked
					if (controllerTx != null)
						return tx;

					issuerTx = tx;
				}
			}
		}

		return controllerTx != null ? controllerTx : issuerTx;
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
			if (!request.isValid()) {
				stat.invalidCredentialRequest();
				throw new DIDTransactionException("Invalid ID transaction request.");
			}
		} catch (DIDResolveException e) {
			stat.invalidCredentialRequest();
			log.error("INTERNAL - resolve failed when verify the id transaction", e);
			throw new DIDTransactionException("Resove DID error");
		}

		CredentialTransaction declareTx = getCredentialDeclareTransaction(request.getCredentialId());
		CredentialTransaction revokeTx = null;

		switch (request.getOperation()) {
		case DECLARE:
			stat.declareCredential();

			if (declareTx != null) { // Declared already
				stat.declareCredentialAlreadyDeclared();
				throw new DIDTransactionException("Credential already exists.");
			}

			revokeTx = getCredentialRevokeTransaction(
					request.getCredentialId(), request.getCredential().getIssuer());
			if (revokeTx != null) { // Revoked already
				stat.declareCredentialAlreadyRevoked();
				throw new DIDTransactionException("Credential already revoked by "
						+ revokeTx.getRequest().getProof().getVerificationMethod().getDid());
			}

			break;

		case REVOKE:
			stat.revokeCredential();
			DID signer = request.getProof().getVerificationMethod().getDid();
			DID issuer = null;
			VerifiableCredential vc = null;

			if (declareTx != null) {
				stat.revokeCredentialNotDeclared();
				vc = declareTx.getRequest().getCredential();
				issuer = vc.getIssuer();
			} else {
				stat.revokeCredentialAlreadyDeclared();
				issuer = signer;
			}

			revokeTx = getCredentialRevokeTransaction(request.getCredentialId(), issuer);
			if (revokeTx != null) {
				stat.revokeCredentialAlreadyRevoked();
				throw new DIDTransactionException("Credential already revoked by "
						+ revokeTx.getRequest().getProof().getVerificationMethod().getDid());
			}

			if (vc != null) {
				DIDDocument ownerDoc = getLastDidDocument(vc.getSubject().getId());
				DIDDocument issuerDoc = getLastDidDocument(vc.getIssuer());

				if (!ownerDoc.getSubject().equals(signer) &&
						!ownerDoc.hasController(signer) &&
						!issuerDoc.getSubject().equals(signer) &&
						!issuerDoc.hasController(signer)) {
					stat.invalidCredentialRequest();
					throw new DIDTransactionException("Invalid ID transaction request.");
				}
			}

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

		stat.resolveCredential();
		if (request.getIssuer() != null)
			stat.resolveCredentialWithIssuer();
		else
			stat.resolveCredentialWithoutIssuer();

		CredentialTransaction declareTx = getCredentialDeclareTransaction(request.getId());

		DID issuer = declareTx != null ? declareTx.getRequest().getCredential().getIssuer()
				: request.getIssuer();
		CredentialTransaction revokeTx = getCredentialRevokeTransaction(request.getId(), issuer);

		CredentialBiography bio = new CredentialBiography(request.getId());
		if (revokeTx != null) {
			stat.resolveRevokedCredential();
			bio.setStatus(CredentialBiography.Status.REVOKED);
			bio.addTransaction(revokeTx);
			if (declareTx != null)
				bio.addTransaction(declareTx);
		} else {
			if (declareTx != null) {
				bio.setStatus(CredentialBiography.Status.VALID);
				bio.addTransaction(declareTx);
			} else {
				stat.resolveNonExistsCredential();
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

		stat.listCredentials();
		if (skip == 0)
			stat.listCredentialsWithoutSkip();
		else
			stat.listCredentialsWithSkip();

		if (limit == CredentialList.DEFAULT_SIZE)
			stat.listCredentialsWithDefaultLimit();
		else if(limit == CredentialList.MAX_SIZE)
			stat.listCredentialsWithMaxLimit();
		else
			stat.listCredentialsWithUserLimit();

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

	/**
	 * Start the simulated ID chain begin to serve the HTTP requests.
	 *
	 * <p>
	 * NOTICE: The start() method is a non-block call. the method will return
	 * immediately, the HTTP server will run in background threads. if you want
	 * to block current thread until the HTTP server shutdown graceful,
	 * use run() instead of start().
	 * </p>
	 *
	 * @throws IOException if there is a error when start the HTTP server
	 */
	public synchronized void start() throws IOException {
		HttpServer server = HttpServer.create(new InetSocketAddress(host, port), 0);
		ThreadPoolExecutor executor = (ThreadPoolExecutor)Executors.newFixedThreadPool(10);
		executor.setThreadFactory(new HttpServerThreadFactory());
		server.setExecutor(executor);

		server.createContext("/resolve", new ResolveHandler());
		server.createContext("/idtx", new IdtxHandler());
		server.createContext("/reset", new ResetHandler());
		server.createContext("/shutdown", new ShutdownHandler());

		stat.reset();
		server.start();

		this.server = server;
		this.executor = executor;

		log.info("Simulated IDChain started on {}:{}", host, port);
	}

	/**
	 * Start the simulated ID chain begin to serve the HTTP requests, this
	 * method will block current thread until the HTTP server shutdown graceful.
	 *
	 * @throws IOException if there is a error when start the HTTP server
	 * @throws InterruptedException if interrupted by the signals
	 * @see start()
	 */
	public synchronized void run() throws IOException, InterruptedException {
		start();
		this.wait();
	}

	/**
	 * Shutdown the simulated ID chain, stop to serve any request.
	 */
	public synchronized void stop() {
		if (server == null)
			return;

		server.stop(0);
		executor.shutdown();
		reset();
		server = null;

		this.notifyAll();

		log.info("Simulated IDChain stopped");
	}

	public String getStatistics() {
		return stat.toString();
	}

	/**
	 * Get the DIDAdapter instance that backed by this simulated ID chain.
	 *
	 * @return the DIDAdapter instance
	 */
	public DIDAdapter getAdapter() {
		if (adapter == null) {
			try {
				adapter = new SimulatedIDChainAdapter(
					new URL("http", host, port, "/"));
			} catch (MalformedURLException ignore) {
				log.error("INTERNAL - error create DIDAdapter", ignore);
			}
		}

		return adapter;
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
				exchange.sendResponseHeaders(400, 0);
				exchange.getResponseBody().close();
				return;
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
				log.trace("ID chain request JSON:\n{}", requestJson.toPrettyString());
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
				exchange.sendResponseHeaders(400, 0);
				exchange.getResponseBody().close();
				return;
			}
		}
	}

	private Map<String, String> queryToMap(String query) {
	    Map<String, String> result = new HashMap<String, String>();

	    if (query == null || query.isEmpty())
	    	return result;

	    for (String param : query.split("&")) {
	        String[] entry = param.split("=");
	        if (entry.length > 1) {
	            result.put(entry[0], entry[1]);
	        }else{
	            result.put(entry[0], "");
	        }
	    }
	    return result;
	}

	private class ResetHandler implements HttpHandler {
		@Override
		public void handle(HttpExchange exchange) throws IOException {
			if (!exchange.getRequestMethod().equals("POST")) {
				log.error("Invalid resolve request, should use POST method");
				exchange.sendResponseHeaders(400, 0);
				exchange.getResponseBody().close();
				return;
			}

			String query = exchange.getRequestURI().getQuery();
			Map<String, String> map = queryToMap(query);

			if (map.containsKey("idtxsonly"))
				resetIdtxs();
			else if (map.containsKey("vctxsonly"))
				resetVctxs();
			else
				reset();

			exchange.sendResponseHeaders(200, 0);
			exchange.getResponseBody().close();
		}
	}

	private class ShutdownHandler implements HttpHandler {
		@Override
		public void handle(HttpExchange exchange) throws IOException {
			if (!exchange.getRequestMethod().equals("POST")) {
				log.error("Invalid resolve request, should use POST method");
				exchange.sendResponseHeaders(400, 0);
				exchange.getResponseBody().close();
				return;
			}

			exchange.sendResponseHeaders(202, 0);
			exchange.getResponseBody().close();

			stop();
		}
	}

	private static class Statistics {
		// General
		private AtomicInteger invalidDidRequest = new AtomicInteger();
		private AtomicInteger invalidDidRequestWithInvalidDocument = new AtomicInteger();
		private AtomicInteger invalidDidRequestOnDeactivatedDid = new AtomicInteger();
		private AtomicInteger invalidCredentialRequest = new AtomicInteger();

		// DID transactions
		private AtomicInteger createDid = new AtomicInteger();
		private AtomicInteger createDidAlreadyExists = new AtomicInteger();
		private AtomicInteger createCustomizedDid = new AtomicInteger();
		private AtomicInteger createCustomizedDidWithSingleController = new AtomicInteger();
		private AtomicInteger createCustomizedDidWithMultiController = new AtomicInteger();
		private AtomicInteger createCustomizedDidWithMultisig = new AtomicInteger();
		private AtomicInteger createCustomizedDidWithSinglesig = new AtomicInteger();

		private AtomicInteger updateDid = new AtomicInteger();
		private AtomicInteger updateDidNotExists = new AtomicInteger();
		private AtomicInteger updateDidWithWrongTxid = new AtomicInteger();
		private AtomicInteger updateCustomizedDid = new AtomicInteger();
		private AtomicInteger updateCustomizedDidWithSingleController = new AtomicInteger();
		private AtomicInteger updateCustomizedDidWithMultiController = new AtomicInteger();
		private AtomicInteger updateCustomizedDidWithMultisig = new AtomicInteger();
		private AtomicInteger updateCustomizedDidWithSinglesig = new AtomicInteger();
		private AtomicInteger updateCustomizedDidWithControllersChanged = new AtomicInteger();

		private AtomicInteger transferDid = new AtomicInteger();
		private AtomicInteger transferDidNotExists = new AtomicInteger();
		private AtomicInteger transferDidWithInvalidTicket = new AtomicInteger();
		private AtomicInteger transferDidWithInvalidTicketId = new AtomicInteger();
		private AtomicInteger transferDidWithInvalidTicketTo = new AtomicInteger();
		private AtomicInteger transferDidWithInvalidController = new AtomicInteger();

		private AtomicInteger deactivateDid = new AtomicInteger();
		private AtomicInteger deactivateDidNotExists = new AtomicInteger();
		private AtomicInteger deactivateDidByOwner = new AtomicInteger();
		private AtomicInteger deactivateDidByAuthroization = new AtomicInteger();

		// Resolve DID
		private AtomicInteger resolveDid = new AtomicInteger();
		private AtomicInteger resolveDidWithAll = new AtomicInteger();
		private AtomicInteger resolveDidNonAll = new AtomicInteger();
		private AtomicInteger resolveNonExistsDid = new AtomicInteger();
		private AtomicInteger resolveDeactivatedDid = new AtomicInteger();

		// Credential transactions
		private AtomicInteger declareCredential = new AtomicInteger();
		private AtomicInteger declareCredentialAlreadyDeclared = new AtomicInteger();
		private AtomicInteger declareCredentialAlreadyRevoked = new AtomicInteger();
		private AtomicInteger revokeCredential = new AtomicInteger();
		private AtomicInteger revokeCredentialAlreadyDeclared = new AtomicInteger();
		private AtomicInteger revokeCredentialAlreadyRevoked = new AtomicInteger();
		private AtomicInteger revokeCredentialNotDeclared = new AtomicInteger();

		// Resolve credential
		private AtomicInteger resolveCredential = new AtomicInteger();
		private AtomicInteger resolveCredentialWithIssuer = new AtomicInteger();
		private AtomicInteger resolveCredentialWithoutIssuer = new AtomicInteger();
		private AtomicInteger resolveNonExistsCredential = new AtomicInteger();
		private AtomicInteger resolveRevokedCredential = new AtomicInteger();

		// List credential
		private AtomicInteger listCredentials = new AtomicInteger();
		private AtomicInteger listCredentialsWithoutSkip = new AtomicInteger();
		private AtomicInteger listCredentialsWithSkip = new AtomicInteger();
		private AtomicInteger listCredentialsWithDefaultLimit = new AtomicInteger();
		private AtomicInteger listCredentialsWithMaxLimit = new AtomicInteger();
		private AtomicInteger listCredentialsWithUserLimit = new AtomicInteger();

		public void reset() {
			for (Field field : getClass().getDeclaredFields()) {
			   // field.setAccessible(true);
				if (!field.getType().equals(AtomicInteger.class))
					continue;

				try {
					AtomicInteger v = (AtomicInteger)field.get(this);
					v.set(0);
				} catch (Exception e) {
					throw new UnknownInternalException(e);
				}
			}
		}

		public int invalidDidRequest() {
			return invalidDidRequest.incrementAndGet();
		}

		public int invalidDidRequestWithInvalidDocument() {
			return invalidDidRequestWithInvalidDocument.incrementAndGet();
		}

		public int invalidDidRequestOnDeactivatedDid() {
			return invalidDidRequestOnDeactivatedDid.incrementAndGet();
		}

		public int invalidCredentialRequest() {
			return invalidCredentialRequest.incrementAndGet();
		}

		public int createDid() {
			return createDid.incrementAndGet();
		}

		public int createDidAlreadyExists() {
			return createDidAlreadyExists.incrementAndGet();
		}

		public int createCustomizedDid() {
			return createCustomizedDid.incrementAndGet();
		}

		public int createCustomizedDidWithSingleController() {
			return createCustomizedDidWithSingleController.incrementAndGet();
		}

		public int createCustomizedDidWithMultiController() {
			return createCustomizedDidWithMultiController.incrementAndGet();
		}

		public int createCustomizedDidWithMultisig() {
			return createCustomizedDidWithMultisig.incrementAndGet();
		}

		public int createCustomizedDidWithSinglesig() {
			return createCustomizedDidWithSinglesig.incrementAndGet();
		}

		public int updateDid() {
			return updateDid.incrementAndGet();
		}

		public int updateDidNotExists() {
			return updateDidNotExists.incrementAndGet();
		}

		public int updateDidWithWrongTxid() {
			return updateDidWithWrongTxid.incrementAndGet();
		}

		public int updateCustomizedDid() {
			return updateCustomizedDid.incrementAndGet();
		}

		public int updateCustomizedDidWithSingleController() {
			return updateCustomizedDidWithSingleController.incrementAndGet();
		}

		public int updateCustomizedDidWithMultiController() {
			return updateCustomizedDidWithMultiController.incrementAndGet();
		}

		public int updateCustomizedDidWithMultisig() {
			return updateCustomizedDidWithMultisig.incrementAndGet();
		}

		public int updateCustomizedDidWithSinglesig() {
			return updateCustomizedDidWithSinglesig.incrementAndGet();
		}

		public int updateCustomizedDidWithControllersChanged() {
			return updateCustomizedDidWithControllersChanged.incrementAndGet();
		}

		public int transferDid() {
			return transferDid.incrementAndGet();
		}

		public int transferDidNotExists() {
			return transferDidNotExists.incrementAndGet();
		}

		public int transferDidWithInvalidTicket() {
			return transferDidWithInvalidTicket.incrementAndGet();
		}

		public int transferDidWithInvalidTicketId() {
			return transferDidWithInvalidTicketId.incrementAndGet();
		}

		public int transferDidWithInvalidTicketTo() {
			return transferDidWithInvalidTicketTo.incrementAndGet();
		}

		public int transferDidWithInvalidController() {
			return transferDidWithInvalidController.incrementAndGet();
		}

		public int deactivateDid() {
			return deactivateDid.incrementAndGet();
		}

		public int deactivateDidNotExists() {
			return deactivateDidNotExists.incrementAndGet();
		}

		public int deactivateDidByOwner() {
			return deactivateDidByOwner.incrementAndGet();
		}

		public int deactivateDidByAuthroization() {
			return deactivateDidByAuthroization.incrementAndGet();
		}

		public int resolveDid() {
			return resolveDid.incrementAndGet();
		}

		public int resolveDidWithAll() {
			return resolveDidWithAll.incrementAndGet();
		}

		public int resolveDidNonAll() {
			return resolveDidNonAll.incrementAndGet();
		}

		public int resolveNonExistsDid() {
			return resolveNonExistsDid.incrementAndGet();
		}

		public int resolveDeactivatedDid() {
			return resolveDeactivatedDid.incrementAndGet();
		}


		public int declareCredential() {
			return declareCredential.incrementAndGet();
		}

		public int declareCredentialAlreadyRevoked() {
			return declareCredentialAlreadyRevoked.incrementAndGet();
		}

		public int declareCredentialAlreadyDeclared() {
			return declareCredentialAlreadyDeclared.incrementAndGet();
		}

		public int revokeCredential() {
			return revokeCredential.incrementAndGet();
		}

		public int revokeCredentialAlreadyRevoked() {
			return revokeCredentialAlreadyRevoked.incrementAndGet();

		}

		public int revokeCredentialAlreadyDeclared() {
			return revokeCredentialAlreadyDeclared.incrementAndGet();
		}

		public int revokeCredentialNotDeclared() {
			return revokeCredentialNotDeclared.incrementAndGet();
		}

		public int resolveCredential() {
			return resolveCredential.incrementAndGet();
		}

		public int resolveCredentialWithIssuer() {
			return resolveCredentialWithIssuer.incrementAndGet();
		}

		public int resolveCredentialWithoutIssuer() {
			return resolveCredentialWithoutIssuer.incrementAndGet();
		}

		public int resolveNonExistsCredential() {
			return resolveNonExistsCredential.incrementAndGet();
		}

		public int resolveRevokedCredential() {
			return resolveRevokedCredential.incrementAndGet();
		}

		public int listCredentials() {
			return listCredentials.incrementAndGet();
		}

		public int listCredentialsWithoutSkip() {
			return listCredentialsWithoutSkip.incrementAndGet();
		}

		public int listCredentialsWithSkip() {
			return listCredentialsWithSkip.incrementAndGet();
		}

		public int listCredentialsWithDefaultLimit() {
			return listCredentialsWithDefaultLimit.incrementAndGet();
		}

		public int listCredentialsWithMaxLimit() {
			return listCredentialsWithMaxLimit.incrementAndGet();
		}

		public int listCredentialsWithUserLimit() {
			return listCredentialsWithUserLimit.incrementAndGet();
		}

		@Override
		public String toString() {
			StringBuffer buff = new StringBuffer(1024);

			buff.append("========================================================\n")
				.append("Statistics of the simulated ID chain\n")
				.append("+ General: \n")
				.append("  * Invalid DID request: ").append(invalidDidRequest.intValue()).append("\n")
				.append("  * Invalid DID request(invalid doc): ").append(invalidDidRequestWithInvalidDocument.intValue()).append("\n")
				.append("  * Invalid DID request(deactivated): ").append(invalidDidRequestOnDeactivatedDid.intValue()).append("\n")
				.append("  * Invalid Credential request: ").append(invalidCredentialRequest.intValue()).append("\n")

				.append("+ Create DID: ").append(createDid.intValue()).append("\n")
				.append("  * Create DID(already exists): ").append(createDidAlreadyExists.intValue()).append("\n")
				.append("  - Create customized DID: ").append(createCustomizedDid.intValue()).append("\n")
				.append("  - Create customized DID(SingleCtrl): ").append(createCustomizedDidWithSingleController.intValue()).append("\n")
				.append("  - Create customized DID(MultiCtrl): ").append(createCustomizedDidWithMultiController.intValue()).append("\n")
				.append("  - Create customized DID(SingleSig: ").append(createCustomizedDidWithSinglesig.intValue()).append("\n")
				.append("  - Create customized DID(MultiSig): ").append(createCustomizedDidWithMultisig.intValue()).append("\n")

				.append("+ Update DID: ").append(updateDid.intValue()).append("\n")
				.append("  * Update DID(not exists): ").append(updateDidNotExists.intValue()).append("\n")
				.append("  * Update DID(wrong txid): ").append(updateDidWithWrongTxid.intValue()).append("\n")
				.append("  - Update customized DID: ").append(updateCustomizedDid.intValue()).append("\n")
				.append("  - Update customized DID(SingleCtrl): ").append(updateCustomizedDidWithSingleController.intValue()).append("\n")
				.append("  - Update customized DID(MultiCtrl): ").append(updateCustomizedDidWithMultiController.intValue()).append("\n")
				.append("  - Update customized DID(SingleSig: ").append(updateCustomizedDidWithSinglesig.intValue()).append("\n")
				.append("  - Update customized DID(MultiSig): ").append(updateCustomizedDidWithMultisig.intValue()).append("\n")
				.append("  * Update customized DID(controllers changed): ").append(updateCustomizedDidWithControllersChanged.intValue()).append("\n")

				.append("+ Transfer DID: ").append(transferDid.intValue()).append("\n")
				.append("  * Transfer DID(not exists): ").append(transferDidNotExists.intValue()).append("\n")
				.append("  * Transfer DID(invalid ticket): ").append(transferDidWithInvalidTicket.intValue()).append("\n")
				.append("  * Transfer DID(invalid ticket id: ").append(transferDidWithInvalidTicketId.intValue()).append("\n")
				.append("  * Transfer DID(invalid ticket to): ").append(transferDidWithInvalidTicketTo.intValue()).append("\n")
				.append("  * Transfer DID(invalid controller): ").append(transferDidWithInvalidController.intValue()).append("\n")

				.append("+ Deactivate DID: ").append(deactivateDid.intValue()).append("\n")
				.append("  * Deactivate DID(not exists): ").append(deactivateDidNotExists.intValue()).append("\n")
				.append("  - Deactivate DID(owner): ").append(deactivateDidByOwner.intValue()).append("\n")
				.append("  - Deactivate DID(authorization):").append(deactivateDidByAuthroization.intValue()).append("\n")

				.append("+ Resolve DID: ").append(resolveDid.intValue()).append("\n")
				.append("  - Resolve DID(all=true): ").append(resolveDidWithAll.intValue()).append("\n")
				.append("  - Resolve DID(all=false): ").append(resolveDidNonAll.intValue()).append("\n")
				.append("  - Resolve non-exists DID: ").append(resolveNonExistsDid.intValue()).append("\n")
				.append("  - Resolve deactivated DID: ").append(resolveDeactivatedDid.intValue()).append("\n")

				.append("+ Declare credential: ").append(declareCredential.intValue()).append("\n")
				.append("  * Declare credential(declared): ").append(declareCredentialAlreadyDeclared.intValue()).append("\n")
				.append("  * Declare credential(revoked): ").append(declareCredentialAlreadyRevoked.intValue()).append("\n")

				.append("+ Revoke credential: ").append(revokeCredential.intValue()).append("\n")
				.append("  - Revoke credential(declared): ").append(revokeCredentialAlreadyDeclared.intValue()).append("\n")
				.append("  - Revoke credential(revoked): ").append(revokeCredentialAlreadyRevoked.intValue()).append("\n")
				.append("  - Revoke credential(not declared): ").append(revokeCredentialNotDeclared.intValue()).append("\n")

				.append("+ Resolve credential: ").append(resolveCredential.intValue()).append("\n")
				.append("  - Resolve credential(withIssuer): ").append(resolveCredentialWithIssuer.intValue()).append("\n")
				.append("  - Resolve credential(withoutIssuer): ").append(resolveCredentialWithoutIssuer.intValue()).append("\n")
				.append("  - Resolve non-exists credential: ").append(resolveNonExistsCredential.intValue()).append("\n")
				.append("  - Resolve revoked credential: ").append(resolveRevokedCredential.intValue()).append("\n")

				.append("+ List credentials: ").append(listCredentials.intValue()).append("\n")
				.append("  - List credential(withoutSkip): ").append(listCredentialsWithoutSkip.intValue()).append("\n")
				.append("  - list credential(withSkip): ").append(listCredentialsWithSkip.intValue()).append("\n")
				.append("  - list credential(withDefaultLimit): ").append(listCredentialsWithDefaultLimit.intValue()).append("\n")
				.append("  - list credential(withMaxLimit): ").append(listCredentialsWithMaxLimit.intValue()).append("\n")
				.append("  - list credential(withUserLimit): ").append(listCredentialsWithUserLimit.intValue()).append("\n")
				.append("========================================================\n");

			return buff.toString();
		}
	}
}