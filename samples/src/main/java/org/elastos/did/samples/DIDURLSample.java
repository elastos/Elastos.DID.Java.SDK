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

import org.elastos.did.DID;
import org.elastos.did.DIDURL;

/**
 * How to use DIDURL object.
 */
public class DIDURLSample {
	public void createFromString() {
		String urlString = "did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2#test";

		DIDURL url = new DIDURL(urlString);

		// output: did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2
		System.out.println(url.getDid());
		// output: test
		System.out.println(url.getFragment());
	}

	public void createFromParts() {
		DID did = new DID("did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2");

		// create a url from a DID object and a relative url
		DIDURL url = new DIDURL(did, "/vcs/abc?opt=false&value=1#test");

		// output: did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2/vcs/abc?opt=false&value=1#test
		System.out.println(url.toString());

		// output: did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2
		System.out.println(url.getDid());
		// output: /vcs/abc
		System.out.println(url.getPath());
		// output: opt=false&value=1
		System.out.println(url.getQueryString());
		// output: test
		System.out.println(url.getFragment());
	}

	public void createWithBuilder() {
		DID did = new DID("did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2");

		DIDURL url = new DIDURL.Builder(did)
				.setPath("/vcs/abc")
				.setQueryParameter("opt","false")
				.setQueryParameter("value", "1")
				.setFragment("test")
				.build();

		// output: did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2/vcs/abc?opt=false&value=1#test
		System.out.println(url.toString());

		// output: did:elastos:iXyYFboFAd2d9VmfqSvppqg1XQxBtX9ea2
		System.out.println(url.getDid());
		// output: /vcs/abc
		System.out.println(url.getPath());
		// output: opt=false&value=1
		System.out.println(url.getQueryString());
		// output: test
		System.out.println(url.getFragment());
	}

	public static void main(String[] args) {
		DIDURLSample sample = new DIDURLSample();

		sample.createFromString();
		sample.createFromParts();
		sample.createWithBuilder();
	}
}
