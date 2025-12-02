package org.suche.gitblit.hooks;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.tika.metadata.Metadata;
import org.apache.tika.parser.AutoDetectParser;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.parser.Parser;
import org.apache.tika.sax.BodyContentHandler;

public class TikaScanner {
	private static final Logger LOG = Logger.getLogger(GitBlitSecCheckReceiveHook.class.getCanonicalName());

	public static String parse(final byte[] content) {
		final var parser   = (Parser)new AutoDetectParser();
		final var sw       = new StringWriter();
		final var handler  = new BodyContentHandler(sw);
		final var metadata = new Metadata();
		final var pc       = new ParseContext();
		final var stream   = new ByteArrayInputStream(content);
		try {
			parser.parse(stream, handler, metadata, pc);
			return sw.toString();
		} catch(final Throwable t) {
			LOG.log(Level.WARNING, "parse() => "+t.getMessage(), t);
			return null;
		}
	}
}