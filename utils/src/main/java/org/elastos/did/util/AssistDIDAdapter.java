package org.elastos.did.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.elastos.did.DID;
import org.elastos.did.DIDEntity;
import org.elastos.did.DefaultDIDAdapter;
import org.elastos.did.backend.DIDRequest;
import org.elastos.did.exception.DIDSyntaxException;
import org.elastos.did.exception.DIDTransactionException;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;

public class AssistDIDAdapter extends DefaultDIDAdapter {
    private static final String MAINNET_RPC_ENDPOINT = "https://assist-restapi.tuum.tech/v2";
    private static final String TESTNET_RPC_ENDPOINT = "https://assist-restapi-testnet.tuum.tech/v2";

    private static final String API_KEY = "IdSFtQosmCwCB9NOLltkZrFy5VqtQn8QbxBKQoHPw7zp3w0hDOyOYjgL53DO3MDH";

    private String assistRpcEndpoint;

	public AssistDIDAdapter(String network) {
		super(network);

		switch (network.toLowerCase()) {
		case "mainnet":
			assistRpcEndpoint = MAINNET_RPC_ENDPOINT;
			break;

		case "testnet":
			assistRpcEndpoint = TESTNET_RPC_ENDPOINT;
			break;

		default:
			break;
		}
	}

	@Override
	public void createIdTransaction(String payload, String memo)
			throws DIDTransactionException {
		if (payload == null || payload.isEmpty())
			throw new IllegalArgumentException("Invalid payload parameter");

		System.out.println("ID transaction payload:");
		try {
			CommandBase.printJson(System.out, false, payload);
		} catch (IOException e) {
			throw new DIDTransactionException(e);
		}

		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Authorization", API_KEY);

		AssistDIDRequest request = null;
		try {
			request = new AssistDIDRequest(payload, memo);
		} catch (DIDSyntaxException e) {
			 throw new IllegalArgumentException("Invalid transaction payload", e);
		}

		AssistDIDResponse response = null;
		try {
			URL createDid = new URL(assistRpcEndpoint + "/didtx/create");
			InputStream is = httpPost(createDid, headers, request.toString());
			response = AssistDIDResponse.parse(is, AssistDIDResponse.class);
		} catch (Exception e) {
			throw new DIDTransactionException("Access the Assist API error.", e);
		}

		if (response.meta.code != 200 || response.data.confirmationId == null)
			throw new DIDTransactionException("Asssit API error: " + response.meta.code
						+ ", message: " + response.meta.message);

		try {
			URL txStatus = new URL(assistRpcEndpoint + "/didtx/confirmation_id/" + response.data.confirmationId);

			retry:
			while (true) {
				InputStream is = httpGet(txStatus, headers);
				AssistTxStatus statusResponse = AssistTxStatus.parse(is, AssistTxStatus.class);
				if (statusResponse.meta.code != 200 || statusResponse.data.status == null)
					throw new DIDTransactionException("Asssit API error: " + response.meta.code
							+ ", message: " + response.meta.message);

				System.out.format("DID transaction %s is %s\n",
						statusResponse.data.blockchainTxId != null ? statusResponse.data.blockchainTxId : "n/a",
						statusResponse.data.status);

				switch (statusResponse.data.status) {
				case PENDING:
				case PROCESSING:
					Thread.sleep(3000);
					continue;

				case QUARANTINED:
				case ERROR:
					throw new DIDTransactionException("DID transaction " +
							statusResponse.data.blockchainTxId + " is " +
							statusResponse.data.status);

				case COMPLETED:
					break retry;
				}
			}
		} catch (Exception e) {
			throw new DIDTransactionException("Access the Assist API error.", e);
		}
	}

	static enum AssistTransactionStatus {
        PENDING,
        PROCESSING,
        COMPLETED,
        QUARANTINED,
        ERROR;

		@Override
		@JsonValue
		public String toString() {
			return name().toLowerCase();
		}

		@JsonCreator
		public static AssistTransactionStatus fromString(String value) {
			return valueOf(value.toUpperCase());
		}
    }


	static class AssistDIDRequest extends DIDEntity<AssistDIDRequest> {
		@JsonProperty("did")
		protected DID did;
		@JsonProperty("memo")
		protected String memo;
		@JsonProperty("requestFrom")
		protected String agent;
		@JsonProperty("didRequest")
		protected DIDRequest request;

		public AssistDIDRequest(String payload, String memo)
				throws DIDSyntaxException {
			this.request = DIDRequest.parse(payload, DIDRequest.class);
			this.did = request.getDid();
			this.memo = memo == null ? "" : memo;
			this.agent = "DID command line utils";
		}
	}

	static class AssistDIDResponseMeta {
		@JsonProperty("code")
		protected long code;
		@JsonProperty("message")
		protected String message;
	}

	static class AssistDIDResponseData {
		@JsonProperty("confirmation_id")
		protected String confirmationId;
		@JsonProperty("service_count")
		protected long serviceCount;
		@JsonProperty("duplicate")
		protected boolean duplicate;
	}

	static class AssistDIDResponse extends DIDEntity<AssistDIDResponse> {
		@JsonProperty("meta")
		AssistDIDResponseMeta meta;
		@JsonProperty("data")
		AssistDIDResponseData data;
	}

	static class AssistTxStatusData {
		@JsonProperty("id")
		protected String id;
		@JsonProperty("did")
		protected String did;
		@JsonProperty("requestFrom")
		protected String agent;
		@JsonProperty("status")
		protected AssistTransactionStatus status;
		@JsonProperty("blockchainTxId")
		protected String blockchainTxId;
	}

	static class AssistTxStatus extends DIDEntity<AssistTxStatus> {
		@JsonProperty("meta")
		AssistDIDResponseMeta meta;
		@JsonProperty("data")
		AssistTxStatusData data;
	}
}
