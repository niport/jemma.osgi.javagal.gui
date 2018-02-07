/**
 * This file is part of JEMMA - http://jemma.energy-home.org
 * (C) Copyright 2013 Telecom Italia (http://www.telecomitalia.it)
 *
 * JEMMA is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License (LGPL) version 3
 * or later as published by the Free Software Foundation, which accompanies
 * this distribution and is available at http://www.gnu.org/licenses/lgpl.html
 *
 * JEMMA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License (LGPL) for more details.
 *
 */
package org.energy_home.jemma.javagal.gui;

import java.io.IOException;
import java.net.URL;
import java.util.StringTokenizer;

import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.http.HttpContext;
import org.osgi.service.useradmin.Authorization;
import org.osgi.service.useradmin.Group;
import org.osgi.service.useradmin.Role;
import org.osgi.service.useradmin.User;
import org.osgi.service.useradmin.UserAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is the main Java GAL UI SCR component. It implements also the
 * HttpContext interface for user authentication.
 * 
 * FIXME: login form authentication do not work anymore.
 * 
 * TODO: use an approach similar to the Http Whiteboard specification, and split this code from the actual web pages.
 *
 */

public class JavaGalWebGuiComponent extends DefaultWebApplication implements HttpContext {

	private static final Logger LOG = LoggerFactory.getLogger(JavaGalWebGuiComponent.class);

	private boolean enableHttps = false;

	private boolean useBasic = true;

	private UserAdmin userAdmin = null;

	private boolean enableSecurity = true;

	private String realm = "javaGalGui Login";

	private String applicationWebAlias = "";

	private static final String ENTRY_HTML_PAGE = "index.html";

	private String defaultUsername = null;

	private String defaultPassword = null;

	private BundleContext bc;

	protected void activate(ComponentContext ctx) {
		synchronized (this) {
			this.bc = ctx.getBundleContext();

			/* default credentials */
			defaultUsername = bc.getProperty("org.energy_home.jemma.username");
			defaultPassword = bc.getProperty("org.energy_home.jemma.password");

			applicationWebAlias = "/" + ctx.getProperties().get("rootContext");

			setRootUrl(applicationWebAlias);

			addResource("/", "webapp");

			setHttpContext(this);

			/* activate the resources */
			registerResources();

			LOG.debug("ZigBee GUI active on {}/{}", applicationWebAlias, ENTRY_HTML_PAGE);
		}
	}

	protected void deactivate() {
		synchronized (this) {
			LOG.debug("deactivated");
		}
	}

	protected void bindUserAdmin(UserAdmin s) {
		synchronized (this) {
			this.userAdmin = s;
		}
	}

	protected void unbindUserAdmin(UserAdmin s) {
		synchronized (this) {
			if (this.userAdmin == s)
				this.userAdmin = null;
		}
	}

	public String getMimeType(String page) {
		if (page.endsWith(".manifest")) {
			return "text/cache-manifest";
		} else if (page.endsWith(".css")) {
			return "text/css";
		} else if (page.endsWith(".js")) {
			return "application/javascript";
		} else if (page.endsWith(".html")) {
			return "text/html";
		} else if (page.endsWith(".ico")) {
			return "image/x-icon";
		} else if (page.endsWith(".png")) {
			return "image/png";
		} else
			return null;
	}

	public URL getResource(String name) {
		URL u = null;
		if (name.endsWith("/")) {
			// the resource name ends with slash, defaults to index.html
			name += ENTRY_HTML_PAGE;
		}

		if (name.equals("webapp/"))
			u = this.bc.getBundle().getResource(name + ENTRY_HTML_PAGE);
		else
			u = this.bc.getBundle().getResource(name);
		return u;
	}

	@Override
	public boolean handleSecurity(HttpServletRequest request, HttpServletResponse response) throws IOException {

		if (request.getRequestURI().contains("favicon.ico")) {
			return true;
		} else {
			LOG.debug("Http Request:" + request.getRequestURI());
		}

		if (enableHttps && !request.getScheme().equals("https")) {
			try {
				response.sendError(HttpServletResponse.SC_FORBIDDEN);
			} catch (IOException e) {
				// do nothing
			}
			return false;
		}

		String queryString = request.getRequestURI();

		if (enableSecurity) {
			if (useBasic) {
				String auth = request.getHeader("Authorization");

				if (auth == null) {
					return failAuthorization(request, response);
				}

				StringTokenizer tokens = new StringTokenizer(auth);
				String authscheme = tokens.nextToken();

				if (!authscheme.equals("Basic")) {
					return failAuthorization(request, response);
				}

				String base64credentials = tokens.nextToken();
				String credentials = new String(Base64.decode(base64credentials.getBytes()));
				int colon = credentials.indexOf(':');
				String userid = credentials.substring(0, colon);
				String password = credentials.substring(colon + 1);
				Authorization subject = null;

				try {
					subject = login(request, userid, password);
				} catch (LoginException e) {
					return failAuthorization(request, response);
				}

				request.setAttribute(HttpContext.REMOTE_USER, userid);
				request.setAttribute(HttpContext.AUTHENTICATION_TYPE, authscheme);
				request.setAttribute(HttpContext.AUTHORIZATION, subject);

			} else {
				HttpSession session = request.getSession(true);
				if (queryString.startsWith(applicationWebAlias)) {
					// this is a restricted area so performs login

					if (request.getMethod() == "POST" && session.getValue("javaGallogon.isDone") == null) {
						String username64 = request.getParameter("username");
						String password64 = request.getParameter("password");

						String username = null;
						String password = null;
						try {
							username = new String(Base64.decode(username64.getBytes()));
							password = new String(Base64.decode(password64.getBytes()));
						} catch (Exception e) {
							LOG.error("Error decoding user/password");
							return false;
						}

						if (!allowUser(username, password)) {
							return redirectToLoginPage(request, response);
						} else {
							session.putValue("javaGallogon.isDone", username);
							try {
								String target = (String) session.getValue("javaGalLogin.target");
								if (target != null) {

									response.sendRedirect(target);
								} else {
									response.sendRedirect(applicationWebAlias + "/" + ENTRY_HTML_PAGE);
								}
							} catch (Exception ignored) {
								return false;
							}
						}
					} else {
						if (queryString.equals(applicationWebAlias + "/login.html")) {
							return true;
						} else {
							session.putValue("javaGalLogin.target", applicationWebAlias + "/" + ENTRY_HTML_PAGE);
							Object done = session.getValue("javaGallogon.isDone");
							if (done == null) {
								if (request.getMethod().equals("GET")) {
									return redirectToLoginPage(request, response);
								} else {
									response.sendError(HttpServletResponse.SC_FORBIDDEN);
									return false;
								}
							}
						}
					}
				}
			}
		}
		return true;
	}

	private boolean redirectToLoginPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String redirect = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + applicationWebAlias
				+ "/login.html";
		response.sendRedirect(redirect);
		return true;
	}

	/**
	 * Checks if the user credentials are correct.
	 * 
	 * @param username
	 *          The username
	 * @param password
	 *          The password
	 * @return True if username and password matches a valid user.
	 */
	protected boolean allowUser(String username, String password) {
		synchronized (this) {
			User user = userAdmin.getUser("username", username);
			if (user != null) {
				if (!user.hasCredential("password", password)) {
					return false;
				}

				/* the user must belong to the administrators group to login */
				Group group = (Group) userAdmin.getRole("Administrators");
				if (group == null) {
					return false;
				}

				for (Role x : group.getMembers()) {
					if (x.getName().equalsIgnoreCase(username))
						return true;
				}
			} else {
				/* use the java system properties */
				if (defaultUsername != null && defaultPassword != null) {
					return (defaultUsername.equals(username) && defaultPassword.equals(password));
				}
			}
		}
		return false;
	}

	private boolean failAuthorization(HttpServletRequest request, HttpServletResponse response) {
		// force a session to be created
		request.getSession(true);
		response.setHeader("WWW-Authenticate", "Basic realm=\"" + realm + "\"");

		try {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		} catch (IOException e) {
			// do nothing
		}
		return false;
	}

	private Authorization login(HttpServletRequest request, final String username, final String password) throws LoginException {
		Authorization auth = (Authorization) request.getAttribute(HttpContext.AUTHORIZATION);
		if (auth != null) {
			return auth;
		}

		if (this.allowUser(username, password)) {
			return auth;
		}

		throw new LoginException();
	}
}
