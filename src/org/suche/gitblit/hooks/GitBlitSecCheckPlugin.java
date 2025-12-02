package org.suche.gitblit.hooks;

import com.gitblit.extensions.GitblitPlugin;

import ro.fortsoft.pf4j.PluginException;
import ro.fortsoft.pf4j.PluginWrapper;
import ro.fortsoft.pf4j.Version;

public class GitBlitSecCheckPlugin extends GitblitPlugin {
	public GitBlitSecCheckPlugin(final PluginWrapper wrapper) { super(wrapper); }

	@Override public void start() throws PluginException {
		// System.out.println("GitBlitSecCheckPlugin.start()");
		super.start();
	}

	@Override public void stop() throws PluginException {
		System.out.println("GitBlitSecCheckPlugin.stop()");
		super.stop();
	}

	@Override public void onInstall() {
		System.out.println("GitBlitSecCheckPlugin.onInstall()");
	}

	@Override public void onUninstall() {
		System.out.println("GitBlitSecCheckPlugin.onUninstall()");
	}

	@Override public void onUpgrade(final Version v) {
		System.out.println("GitBlitSecCheckPlugin.onUpgrade("+v+")");
	}
}