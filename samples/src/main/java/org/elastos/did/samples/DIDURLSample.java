package org.elastos.did.samples;

import org.elastos.did.DID;
import org.elastos.did.DIDURL;

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
