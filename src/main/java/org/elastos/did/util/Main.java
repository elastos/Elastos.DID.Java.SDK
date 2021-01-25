package org.elastos.did.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;

import org.elastos.did.DID;
import org.elastos.did.DIDBackend;
import org.elastos.did.DIDBackend.ResolveHandle;
import org.elastos.did.DIDDocument;
import org.elastos.did.VerifiableCredential;
import org.elastos.did.VerifiablePresentation;
import org.elastos.did.crypto.Base64;
import org.elastos.did.exception.DIDResolveException;
import org.elastos.did.jwt.JwtParser;
import org.elastos.did.jwt.JwtParserBuilder;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

public class Main {
	private static File cacheDir = new File(System.getProperty("user.home") +
			File.separator + ".cache.did.elastos");

	private static String mainnetResolver = "http://api.elastos.io:20606";
	private static String testnetResolver = "http://api.elastos.io:21606";

	public static void setupDIDBackend(String network) throws DIDResolveException {
		String resolver;

		if (network.equalsIgnoreCase("mainnet"))
			resolver = mainnetResolver;
		else if (network.equalsIgnoreCase("testnet"))
			resolver = testnetResolver;
		else
			throw new DIDResolveException("Unknown network :" + network);

		DIDBackend.initialize(resolver, cacheDir);
	}

	public static void printJson(PrintStream out, boolean compact, String json) throws IOException {
		if (!compact) {
			JsonFactory jsonFactory = new JsonFactory();
			jsonFactory.configure(JsonGenerator.Feature.AUTO_CLOSE_TARGET, false);
			jsonFactory.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, false);

			ObjectMapper mapper = new ObjectMapper(jsonFactory);
			JsonNode node = mapper.readTree(json);
			mapper.writerWithDefaultPrettyPrinter().writeValue(out, node);
			out.println();
		} else {
			out.println(json);
		}
	}

	public static class LocalResolveHandle implements ResolveHandle {
		private File didDir;
		private Map<DID, DIDDocument> dids;

		public LocalResolveHandle(String dir) throws IOException {
			if (dir == null || dir.isEmpty())
				didDir = new File(".");
			else
				didDir = new File(dir);

			didDir = didDir.getCanonicalFile();
			dids = new HashMap<DID, DIDDocument>();
		}

		@Override
		public DIDDocument resolve(DID did) {
			if (dids.containsKey(did))
				return dids.get(did);

			try {
				File didFile = new File(didDir, did.getMethodSpecificId());
				if (didFile.exists() && didFile.isFile()) {
					InputStream in = new FileInputStream(didFile);
					DIDDocument doc = DIDDocument.fromJson(in);
					in.close();
					System.out.println("Load did " + did + " from " + didFile.getAbsolutePath());
					dids.put(did, doc);
					return doc;
				}
			} catch (Exception e) {
				System.out.print("Load did  " + did + " error!");
				e.printStackTrace(System.err);
			}

			return null;
		}
	}

	@Command(name = "resolvedid", mixinStandardHelpOptions = true, version = "resolvedid 1.0",
			description = "Resolve DID from the ID side chain.")
	public static class ResolveDid implements Callable<Integer> {
		@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet")
	    private String network = "mainnet";

		@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
	    private boolean force = false;

		@Option(names = {"-c", "--compact"}, description = "Output JSON in compact format, default false.")
	    private boolean compact = false;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
	    private boolean verbose = false;

		@Option(names = {"-o", "--out"}, description = "Output file, default is STDOUT.")
	    private String outputFile;

		@Parameters(paramLabel = "DID", index = "0", description = "The target DID.")
	    private String didstr;

		@Override
		public Integer call() throws Exception {
			try {
				setupDIDBackend(network);

				if (!didstr.startsWith("did:"))
					didstr = "did:elastos:" + didstr;

				DID did = new DID(didstr);

				DIDDocument doc = did.resolve(force);
				if (doc == null) {
					System.out.format("DID %s not exists.\n", did);
				} else {
					PrintStream out = System.out;
					if (outputFile != null)
						out = new PrintStream(outputFile);

					printJson(out, compact, doc.toString(true));

					if (outputFile != null)
						out.close();
				}
			} catch(Exception e) {
				if (verbose)
					e.printStackTrace();
				else
					System.out.println("Error: " + e.getMessage());
			}

			return 0;
		}

	}

	@Command(name = "verifydoc", mixinStandardHelpOptions = true, version = "verifydoc 1.0",
			description = "Verify the DID document.")
	public static class VerifyDocument implements Callable<Integer> {
		@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet")
	    private String network = "mainnet";

		@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
	    private boolean force = false;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
	    private boolean verbose = false;

		@Parameters(paramLabel = "DOCUMENT", index = "0", description = "The DID document filename.")
	    private String documentFile;

		@Override
		public Integer call() throws Exception {
			try {
				setupDIDBackend(network);

				DIDDocument doc = DIDDocument.fromJson(new FileReader(documentFile));
				System.out.format("Genuine: %s\n", doc.isGenuine());
				System.out.format("Expired: %s\n", doc.isExpired());
				System.out.format("Valid:   %s\n", doc.isValid());
			} catch(Exception e) {
				if (verbose)
					e.printStackTrace();
				else
					System.out.println("Error: " + e.getMessage());
			}

			return 0;
		}
	}

	@Command(name = "verifyvc", mixinStandardHelpOptions = true, version = "verifyvc 1.0",
			description = "Verify the verifiable credential.")
	public static class VerifyCredential implements Callable<Integer> {
		@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet")
	    private String network = "mainnet";

		@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
	    private boolean force = false;

		@Option(names = {"-l", "--local"}, description = "Local DID resolve directory.")
	    private String local = null;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
	    private boolean verbose = false;

		@Parameters(paramLabel = "VC", index = "0", description = "The credential filename.")
	    private String credentialFile;

		@Override
		public Integer call() throws Exception {
			try {
				setupDIDBackend(network);
				DIDBackend.setResolveHandle(new LocalResolveHandle(local));

				VerifiableCredential vc = VerifiableCredential.fromJson(new FileReader(credentialFile));
				System.out.format("Genuine: %s\n", vc.isGenuine());
				System.out.format("Expired: %s\n", vc.isExpired());
				System.out.format("Valid:   %s\n", vc.isValid());
			} catch(Exception e) {
				if (verbose)
					e.printStackTrace();
				else
					System.out.println("Error: " + e.getMessage());
			}

			return 0;
		}
	}

	@Command(name = "verifyvp", mixinStandardHelpOptions = true, version = "verifyvp 1.0",
			description = "Verify the verifiable presentation.")
	public static class VerifyPresentation implements Callable<Integer> {
		@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet")
	    private String network = "mainnet";

		@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
	    private boolean force = false;

		@Option(names = {"-l", "--local"}, description = "Local DID resolve directory.")
	    private String local = null;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
	    private boolean verbose = false;

		@Parameters(paramLabel = "VP", index = "0", description = "The presentation filename.")
	    private String presentationFile;

		@Override
		public Integer call() throws Exception {
			try {
				setupDIDBackend(network);
				DIDBackend.setResolveHandle(new LocalResolveHandle(local));

				VerifiablePresentation vp = VerifiablePresentation.fromJson(new FileReader(presentationFile));
				System.out.format("Genuine: %s\n", vp.isGenuine());
				System.out.format("Valid:   %s\n", vp.isValid());
			} catch(Exception e) {
				if (verbose)
					e.printStackTrace();
				else
					System.out.println("Error: " + e.getMessage());
			}

			return 0;
		}
	}

	@Command(name = "verifyjwt", mixinStandardHelpOptions = true, version = "verifyjwt 1.0",
			description = "Verify the JTW/JWS token.")
	public static class VerifyJwt implements Callable<Integer> {
		private static final int BASE64_OPT = Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP;

		@Option(names = {"-n", "--network"}, description = "Avaliable networks: mainnet testnet")
	    private String network = "mainnet";

		@Option(names = {"-f", "--force"}, description = "Resolve froced from ID sidechain, default false.")
	    private boolean force = false;

		@Option(names = {"-l", "--local"}, description = "Local DID resolve directory.")
	    private String local = null;

		@Option(names = {"-c", "--compact"}, description = "Output JSON in compact format, default false.")
	    private boolean compact = false;

		@Option(names = {"-e", "--verbase"}, description = "Verbose error output, default false.")
	    private boolean verbose = false;

		@Parameters(paramLabel = "JWT", index = "0", description = "The JWT token filename.")
	    private String jwtFile;

		@Override
		public Integer call() throws Exception {
			try {
				setupDIDBackend(network);
				DIDBackend.setResolveHandle(new LocalResolveHandle(local));

				BufferedReader in = new BufferedReader(new FileReader(jwtFile));
				String token = in.readLine();
				in.close();

				JwtParser jp = new JwtParserBuilder().build();
				jp.parseClaimsJws(token);

				String[] parts = token.split("\\.", 3);
				System.out.println("======== HEADER ========");
				printJson(System.out, compact, new String(Base64.decode(parts[0].getBytes(), BASE64_OPT)));
				System.out.println("======== PAYLOAD ========");
				printJson(System.out, compact, new String(Base64.decode(parts[1].getBytes(), BASE64_OPT)));
				if (parts.length == 3) {
					System.out.println("======== SIGNATURE ========");
					System.out.println(parts[2]);
				}
			} catch(Exception e) {
				if (verbose)
					e.printStackTrace();
				else
					System.out.println("Error: " + e.getMessage());
			}

			return 0;
		}
	}

	@Command(name = "org.elastos.did.util.Main", description = "Elastos DID command line tool.",
		subcommands = {
		    ResolveDid.class,
		    VerifyDocument.class,
		    VerifyCredential.class,
		    VerifyPresentation.class,
		    VerifyJwt.class
		})
	public static class DIDCommand {
	}

	public static void main(String[] args) {
		int exitCode = new CommandLine(new DIDCommand()).execute(args);
		System.exit(exitCode);
	}

}
