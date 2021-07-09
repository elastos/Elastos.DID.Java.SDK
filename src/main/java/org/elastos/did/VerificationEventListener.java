package org.elastos.did;

public abstract class VerificationEventListener {
	public abstract void done(Object context, boolean succeeded, String message);

	public void succeeded(Object context, String format, Object... args) {
		String message = String.format(format, args);
		done(context, true, message);
	}

	public void failed(Object context, String format, Object... args) {
		String message = String.format(format, args);
		done(context, false, message);
	}
}
