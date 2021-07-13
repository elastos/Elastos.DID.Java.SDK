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

package org.elastos.did;

import java.util.LinkedList;

/**
 * The abstract class VerificationEventListener is a basic method to get
 * the DID object verification events and messages.
 *
 * The user can extends this class to get the verification events and messages.
 */
public abstract class VerificationEventListener {
	/**
	 * This method is called when a DID object verification was finished.
	 *
	 * @param context current DID object
	 * @param succeeded true if the verification is passed, false otherwise
	 * @param message the detailed message
	 */
	public abstract void done(Object context, boolean succeeded, String message);

	/**
	 * Reset current listener to the initial state.
	 *
	 * After reset the listener, it should be safe to reuse.
	 */
	public void reset() {}

	protected void succeeded(Object context, String format, Object... args) {
		String message = String.format(format, args);
		done(context, true, message);
	}

	protected void failed(Object context, String format, Object... args) {
		String message = String.format(format, args);
		done(context, false, message);
	}

	static class DefaultVerificationEventListener extends VerificationEventListener {
		private static final String EMPTY = "";

		private String ident;
		private String succeededPrefix;
		private String failedPrefix;

		private LinkedList<Record> records;

		static class Record {
			Object context;
			boolean succeeded;
			String message;

			Record(Object context, boolean succeeded, String message) {
				this.context = context;
				this.succeeded = succeeded;
				this.message = message;
			}
		}


		public DefaultVerificationEventListener(String ident, String succeededPrefix, String failedPrefix) {
			this.ident = ident == null ? EMPTY : ident;
			this.succeededPrefix = succeededPrefix == null ? EMPTY : succeededPrefix;
			this.failedPrefix = failedPrefix == null ? EMPTY : failedPrefix;

			records = new LinkedList<Record>();
		}

		@Override
		public void done(Object context, boolean succeeded, String message) {
			records.addFirst(new Record(context, succeeded, message));
		}

		@Override
		public void reset() {
			records.clear();
		}

		@Override
		public String toString() {
			StringBuilder strb = new StringBuilder();
			for (Record record : records) {
				strb.append(ident)
					.append(record.succeeded ? succeededPrefix : failedPrefix)
					.append(record.message)
					.append("\n");
			}

			return strb.toString();
		}
	}

	/**
	 * Get the default VerificationEventListener implementation. The listener
	 * will gather all messages and return a stringify result.
	 *
	 * @param ident ident string for each message
	 * @param succeededPrefix prefix string for the succeeded messages
	 * @param failedPrefix prefix string for the failed messages
	 * @return the default VerificationEventListener instance
	 */
	public static VerificationEventListener getDefault(String ident, String succeededPrefix, String failedPrefix) {
		return new DefaultVerificationEventListener(ident, succeededPrefix, failedPrefix);
	}

	/**
	 * Get the default VerificationEventListener implementation. The listener
	 * will gather all messages and return a stringify result.
	 *
	 * @param ident ident string for each message
	 * @return the default VerificationEventListener instance
	 */
	public static VerificationEventListener getDefault(String ident) {
		return new DefaultVerificationEventListener(ident, null, null);
	}
}
