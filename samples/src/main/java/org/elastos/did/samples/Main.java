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

package org.elastos.did.samples;

public class Main {
	public static void main(String[] args) {
		System.out.println("Welcome to Elastos DID examples.");

		System.out.println("\nSample apps:");
		System.out.println("  - DIDURLSample            How to usen the DIDURL object");
		System.out.println("  - InitializeDID           How to initalize the user's or app's DID");
		System.out.println("  - RootIdentitySample      How to use the RootIdentity");
		System.out.println("  - RestoreFromMnemonic     How to restore the identity and DIDs from the backuped mnemonic");
		System.out.println("  - IssueCredential         How to issue a verifiable credential");
		System.out.println("  - CreatePresentation      How to create a verifable presentation from credentials");
		System.out.println("  - JWTSample               How to create and read the JWT token");
		System.out.println("  - PresentationInJWT       How to create a JWT token with presentation");

		System.out.println("\nSample DID adapters:");
		System.out.println("  - Web3Adapter             The DIDAdapter implemented using Web3j");
		System.out.println("  - AssistAdapter           The DIDAdapter implemented using the Tuum Assist API");

		System.out.println("\nInternal classes:");
		System.out.println("  - Entity                  Common class that represent an entity with DID");
	}
}
