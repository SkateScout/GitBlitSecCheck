package org.suche.gitblit.hooks;
import java.io.IOException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import org.eclipse.jgit.diff.DiffEntry;
import org.eclipse.jgit.diff.DiffFormatter;
import org.eclipse.jgit.diff.RawTextComparator;
import org.eclipse.jgit.errors.MissingObjectException;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.transport.ReceiveCommand;
import org.eclipse.jgit.transport.ReceiveCommand.Result;
import org.eclipse.jgit.treewalk.TreeWalk;
import org.eclipse.jgit.util.io.DisabledOutputStream;

import com.gitblit.extensions.ReceiveHook;
import com.gitblit.git.GitblitReceivePack;
import com.moandjiezana.toml.Toml;

import ro.fortsoft.pf4j.Extension;


// https://www.gitblit.com/plugins_extensions.html

@Extension public class GitBlitSecCheckReceiveHook extends ReceiveHook {
	private static final Logger LOG = Logger.getLogger(GitBlitSecCheckReceiveHook.class.getCanonicalName());

	public static       Ruleset ruleset      = null;
	private static final Path    path         = Path.of("etc/gitleaks.toml");
	private static final URI     defaultRules = URI.create("https://raw.githubusercontent.com/gitleaks/gitleaks/refs/heads/master/config/gitleaks.toml");

	static {
		if(Files.exists(path)) {
			try {
				ruleset = Ruleset.of(Files.readString(path));
			} catch(final Throwable t) { LOG.log(Level.SEVERE, "Fetch GitBlitSecCheckReceiveHook rules => "+t.getMessage(), t); }
		} else {
			new Thread(()->{
				try {
					final var bytes = defaultRules.toURL().openStream().readAllBytes();
					LOG.log(Level.INFO, "Download "+defaultRules);
					Files.write(path, bytes);
					LOG.log(Level.INFO, "Stored "+path);
					final var toml = new Toml().read(new String(bytes)).toMap();
					@SuppressWarnings("unchecked") final var r = Ruleset.ofListMap((List<Map<String,Object>>)toml.get("rules"));
					ruleset = r;
				} catch(final UnknownHostException t) { LOG.log(Level.SEVERE, "Fetch GitBlitSecCheckReceiveHook rules from "+defaultRules+" failed. => "+t.getMessage());
				} catch(final Throwable            t) { LOG.log(Level.SEVERE, "Fetch GitBlitSecCheckReceiveHook rules => "+t.getMessage(), t);
				}
			}, "Fetch security rules").start();
		}
	}

	@Override public void onPostReceive(final GitblitReceivePack receivePack, final Collection<ReceiveCommand> commands) { }

	private static final Pattern ignoreFiles = Pattern.compile("(?i)[.](?:eot|[ot]tf|woff2|bmp|gif|jpe?g|png|svg|bin|socket|vsidx|v2|suo|wsuo|dll|pdb|exe|gltf|tiff?)$");
	private static final Pattern tikaFiles   = Pattern.compile("(?i)[.](?:docx?|xlsx?|pdf)$");

	private String scan(final Repository repository, final String path, final ObjectId objectId) throws MissingObjectException, IOException {
		if(ruleset == null) {
			LOG.log(Level.SEVERE, "⚡ Missing ruleset for GitBlitSecCheckReceiveHook");
			return null;
		}
		if(ignoreFiles.matcher(path).find()) return null;
		final var loader    = repository.open(objectId);
		final var bytes = loader.getBytes();
		final var useTika   = tikaFiles.matcher(path).find();
		final var content  = useTika ? TikaScanner.parse(bytes) : new String(bytes);
		if(content == null) return null;
		final var found = ruleset.findMatch(content);
		return (null == found ? null : "Found possible secret ["+found.getKey()+"] via rule ["+found.getValue().id()+"] in file ["+path+"]");
	}

	@Override public void onPreReceive(final GitblitReceivePack receivePack, final Collection<ReceiveCommand> commands) {
		final var repository = receivePack.getRepository();
		final var user       = receivePack.getUserModel();
		try (var revWalk     = receivePack.getRevWalk()) {
			for (final ReceiveCommand cmd : commands) {
				if (cmd.getType() != ReceiveCommand.Type.UPDATE && cmd.getType() != ReceiveCommand.Type.CREATE) continue; // Only process updates and creations (ignore deletes for content scan)
				final var newId     = cmd.getNewId();
				final var oldId     = cmd.getOldId();
				final var newCommit = revWalk.parseCommit(newId);
				final var toScan = new HashMap<ObjectId, String>();
				if(oldId == null) {
					final var tree      = newCommit.getTree();
					final var treeId    = tree.getId();
					try (var treeWalk   = new TreeWalk(repository)) {
						treeWalk.reset(treeId);
						treeWalk.setRecursive(true);
						while (treeWalk.next()) toScan.put(treeWalk.getObjectId(0), treeWalk.getPathString());
					}
				} else {
					final var rw = receivePack.getRevWalk();
					try(final var df = new DiffFormatter(DisabledOutputStream.INSTANCE)) {
						df.setRepository(repository);
						df.setDiffComparator(RawTextComparator.DEFAULT);
						df.setDetectRenames(true);
						final var diffs = df.scan(rw.parseCommit(oldId), newCommit);
						for (final DiffEntry diff : diffs)if(diff.getNewId().toObjectId() instanceof final ObjectId objectId) toScan.put(objectId, diff.getNewPath());
					}
				}
				StringBuilder error = null;
				for(final var e : toScan.entrySet()) if(scan(repository, e.getValue(), e.getKey()) instanceof final String rejection) {
					if(null == error) error = new StringBuilder();
					if(error.isEmpty()) error.append("\n");
					error.append(rejection);
				}
				if(null != error) {
					LOG.log(Level.WARNING, "Reject GIT operation from "+user.displayName+" <"+user.emailAddress+"> found possible secrets");
					cmd.setResult(Result.REJECTED_OTHER_REASON, error.toString());

				}
			}
		} catch (final Exception e) { LOG.log(Level.SEVERE, "onPreReceive() => "+e.getMessage(), e); }
	}
}