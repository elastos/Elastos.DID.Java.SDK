package org.elastos.did.jwt;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;

import org.elastos.did.DIDBackend;
import org.elastos.did.TestConfig;
import org.elastos.did.TestData;
import org.elastos.did.exception.DIDException;
import org.junit.jupiter.api.Test;

public class JwtVerifier {
	// @Test
	public void jwsTestSignWithDefaultKey()
			throws DIDException, IOException, JwtException {
		DIDBackend.initialize(TestConfig.resolver, TestData.getResolverCacheDir());

		String token = "eyJ0eXAiOiJKV1QiLCJjdHkiOiJqc29uIiwibGlicmFyeSI6IkVsYXN0b3MgRElEIiwidmVyc2lvbiI6IjEuMCIsImFsZyI6IkVTMjU2In0.eyJpc3MiOiJkaWQ6ZWxhc3RvczppVHd1MTU1b2JZcWh3R2tibWhlSEJjODFaaVpCWHhud2IxIiwic3ViIjoiSnd0VGVzdCIsImp0aSI6IjAiLCJhdWQiOiJUZXN0IGNhc2VzIiwiaWF0IjoxNjA2MTEwOTUyLCJleHAiOjE2MTQwNTk3NTIsIm5iZiI6MTYwMzQzMjU1MiwiZm9vIjoiYmFyIn0.B9779Cpr0H8yYNeRjaTmHxqIWdvkDMR9owWmyORwmr2hNYy6JV_EUD93QAkOfRhl9votyreDhl0sYgh8bYe12A";
		JwtTest.printJwt(token);

		JwtParser jp = new JwtParserBuilder().build();
		Jws<Claims> jwt = jp.parseClaimsJws(token);
		assertNotNull(jwt);

		String s = jwt.getSignature();
		assertNotNull(s);
	}

}
