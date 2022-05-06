/*
 * Copyright (c) 2022 Elastos Foundation
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

package org.elastos.did.util;

import java.nio.file.Path;
import java.util.concurrent.Callable;
import java.util.function.Supplier;

import org.jline.console.SystemRegistry;
import org.jline.console.impl.Builtins;
import org.jline.console.impl.SystemRegistryImpl;
import org.jline.keymap.KeyMap;
import org.jline.reader.Binding;
import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.MaskingCallback;
import org.jline.reader.Parser;
import org.jline.reader.Reference;
import org.jline.reader.UserInterruptException;
import org.jline.reader.impl.DefaultParser;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.jline.widget.TailTipWidgets;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.shell.jline3.PicocliCommands;
import picocli.shell.jline3.PicocliCommands.PicocliCommandsFactory;

@Command(name = "sh", mixinStandardHelpOptions = true, version = Version.VERSION,
		description = "Interactive shell.")
public class Shell extends CommandBase implements Callable<Integer> {
	private SystemRegistry systemRegistry;
	private LineReader reader;

	public void initCommandLine() {
		Supplier<Path> workDir = () -> DIDUtils.getHome().toPath();
		// set up JLine built-in commands
		Builtins builtins = new Builtins(workDir, null, null);
		DIDUtils commands = new DIDUtils();
		PicocliCommandsFactory factory = new PicocliCommandsFactory();
		CommandLine cmd = new CommandLine(commands, factory);
		PicocliCommands picocliCommands = new PicocliCommands(cmd);

		Parser parser = new DefaultParser();
		try (Terminal terminal = TerminalBuilder.builder().build()) {
			systemRegistry = new SystemRegistryImpl(parser, terminal, workDir, null);
			systemRegistry.setCommandRegistries(builtins, picocliCommands);
			// systemRegistry.register("help", picocliCommands);

			reader = LineReaderBuilder.builder()
					.terminal(terminal)
					.completer(systemRegistry.completer())
					.parser(parser)
					.variable(LineReader.LIST_MAX, 50)   // max tab completion candidates
					.build();
			builtins.setLineReader(reader);

			CommandContext.getInstance().setLineReader(reader);

			factory.setTerminal(terminal);
			TailTipWidgets widgets = new TailTipWidgets(reader, systemRegistry::commandDescription, 5, TailTipWidgets.TipType.COMPLETER);
			widgets.enable();
			KeyMap<Binding> keyMap = reader.getKeyMaps().get("main");
			keyMap.bind(new Reference("tailtip-toggle"), KeyMap.alt("s"));
		} catch (Exception e) {
			e.printStackTrace(System.err);
			System.exit(-1);
		}
	}


	@Override
	public Integer call() throws Exception {
		initCommandLine();

		System.out.println("Network: " + Colorize.green(getActiveNetwork().toString()));
		if (getActiveIdentity() != null) {
			System.out.print("Identity: " + Colorize.green(getActiveIdentity()));
			System.out.println(", DID: " + Colorize.green(String.valueOf(getActiveDid())));
		} else {
			System.out.println("Identity: " + Colorize.yellow("N/A"));
		}

		String prompt = "didshell $ ";
		String rightPrompt = null;

		String line;
		while (true) {
			try {
				systemRegistry.cleanUp();
				line = reader.readLine(prompt, rightPrompt, (MaskingCallback)null, null);
				systemRegistry.execute(line);
			} catch (UserInterruptException e) {
				// Ignore
			} catch (EndOfFileException e) {
				return 0;
			} catch (Exception e) {
				systemRegistry.trace(e);
			}
		}
	}
}
