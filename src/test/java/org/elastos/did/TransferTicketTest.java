package org.elastos.did;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.elastos.did.exception.DIDException;
import org.elastos.did.utils.DIDTestExtension;
import org.elastos.did.utils.TestData;
import org.elastos.did.utils.TestData.CompatibleData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(DIDTestExtension.class)
public class TransferTicketTest {
	private TestData testData;

	@BeforeEach
	public void beforeEach() throws DIDException {
		testData = new TestData();

	}

	@AfterEach
	public void afterEach() {
		testData.cleanup();
	}

	@Test
	public void testMultiSignatureTicket() throws DIDException, IOException {
		CompatibleData cd = testData.getCompatibleData(2);
		cd.loadAll();

		TransferTicket tt = cd.getTransferTicket("foobar");

		assertEquals(new DID("did:elastos:foobar"), tt.getSubject());
		assertEquals(new DID("did:elastos:igHbSCez6H3gTuVPzwNZRrdj92GCJ6hD5d"), tt.getTo());
		assertEquals("4184a30d785a3579e944fd48e40e3cdf", tt.getTransactionId());
		assertEquals(2, tt.getProofs().size());
		assertTrue(tt.isGenuine());
	}

	@Test
	public void testTicket() throws DIDException, IOException {
		CompatibleData cd = testData.getCompatibleData(2);
		cd.loadAll();

		TransferTicket tt = cd.getTransferTicket("baz");

		assertEquals(new DID("did:elastos:baz"), tt.getSubject());
		assertEquals(new DID("did:elastos:igHbSCez6H3gTuVPzwNZRrdj92GCJ6hD5d"), tt.getTo());
		assertEquals("f54c02fd7dcdd2be48a6353998a04811", tt.getTransactionId());
		assertEquals(1, tt.getProofs().size());
		assertTrue(tt.isGenuine());
	}
}
