package org.elastos.did;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class DIDAdapterTests {
	@ParameterizedTest
	@ValueSource(ints = {301, 302, 303, 307})
	public void testRedirect(int code) throws Exception {
		DefaultDIDAdapter adapter = new DefaultDIDAdapter("https://httpstat.us/");

		// get Standard result
		InputStream result = adapter.httpGet(new URL("https://httpstat.us/"));
	    String expected = new BufferedReader(
	    	      new InputStreamReader(result, StandardCharsets.UTF_8))
	    	        .lines()
	    	        .collect(Collectors.joining("\n"));
	    System.out.println(expected);

		result = adapter.httpGet(new URL("https://httpstat.us/" + code));
		assertNotNull(result);
	    String redirected = new BufferedReader(
	    	      new InputStreamReader(result, StandardCharsets.UTF_8))
	    	        .lines()
	    	        .collect(Collectors.joining("\n"));
	    assertEquals(expected, redirected);
	}
}
