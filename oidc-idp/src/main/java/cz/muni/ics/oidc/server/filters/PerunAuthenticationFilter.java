package cz.muni.ics.oidc.server.filters;

import cz.muni.ics.oidc.models.Facility;
import cz.muni.ics.oidc.models.PerunAttributeValue;
import cz.muni.ics.oidc.models.PerunUser;
import cz.muni.ics.oidc.server.PerunAcrRepository;
import cz.muni.ics.oidc.server.PerunPrincipal;
import cz.muni.ics.oidc.server.adapters.PerunAdapter;
import cz.muni.ics.oidc.server.configurations.FacilityAttrsConfig;
import cz.muni.ics.oidc.server.configurations.PerunOidcConfig;
import cz.muni.ics.oidc.web.controllers.PerunUnapprovedController;
import org.mitre.openid.connect.models.Acr;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

import static cz.muni.ics.oidc.server.filters.PerunFilterConstants.*;
import static cz.muni.ics.oidc.server.filters.PerunFilterConstants.AUTHORIZE_REQ_PATTERN;
import static cz.muni.ics.oidc.server.filters.PerunFilterConstants.EFILTER_PREFIX;
import static cz.muni.ics.oidc.server.filters.PerunFilterConstants.FILTER_PREFIX;
import static cz.muni.ics.oidc.server.filters.PerunFilterConstants.IDP_ENTITY_ID_PREFIX;
import static cz.muni.ics.oidc.server.filters.PerunFilterConstants.PARAM_AUTHN_CONTEXT_CLASS_REF;
import static cz.muni.ics.oidc.server.filters.PerunFilterConstants.PARAM_FORCE_AUTHN;
import static cz.muni.ics.oidc.server.filters.PerunFilterConstants.PARAM_LOGGED_OUT;
import static cz.muni.ics.oidc.server.filters.PerunFilterConstants.PARAM_TARGET;
import static cz.muni.ics.oidc.server.filters.PerunFilterConstants.PARAM_WAYF_EFILTER;
import static cz.muni.ics.oidc.server.filters.PerunFilterConstants.PARAM_WAYF_FILTER;
import static cz.muni.ics.oidc.server.filters.PerunFilterConstants.PARAM_WAYF_IDP;
import static cz.muni.ics.oidc.server.filters.PerunFilterConstants.REFEDS_MFA;
import static org.mitre.oauth2.model.RegisteredClientFields.CLIENT_ID;

/**
 * Extracts preauthenticated user id. The user must be already authenticated by Kerberos, Shibboleth, X509,
 * this class only gets extSourceName and extLogin from HTTP request.
 *
 * @author Martin Kuba <makub@ics.muni.cz>
 */
public class PerunAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

	private static final Logger log = LoggerFactory.getLogger(PerunAuthenticationFilter.class);
	private final AntPathRequestMatcher UNAPPROVED = new AntPathRequestMatcher(
			PerunUnapprovedController.UNAPPROVED_MAPPING);
	private final AntPathRequestMatcher AUTHORIZE = new AntPathRequestMatcher(AUTHORIZE_REQ_PATTERN);

	private static final String FILTER_NAME = "AuthenticationFilter";

	private final PerunAdapter perunAdapter;
	private final FacilityAttrsConfig facilityAttrsConfig;
	private final PerunOidcConfig config;
	private final PerunAcrRepository acrRepository;

	@Autowired
	public PerunAuthenticationFilter(PerunAdapter perunAdapter, FacilityAttrsConfig facilityAttrsConfig,
									 PerunOidcConfig config, PerunAcrRepository acrRepository) {
		this.perunAdapter = perunAdapter;
		this.facilityAttrsConfig = facilityAttrsConfig;
		this.config = config;
		this.acrRepository = acrRepository;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException
	{
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;

		PerunPrincipal principal = FiltersUtils.extractPerunPrincipal(req, config.getProxyExtSourceName());
		String clientId = req.getParameter(CLIENT_ID);
		String redirectURL = null;
		if (this.mfaRequestedAndNotPerformedYet(req)) {
			redirectURL = this.buildMfaAuthenticationUrl(req, clientId);
		} else if (req.getParameter(PARAM_FORCE_AUTHN) != null) {
			redirectURL = this.buildForceAuthenticationUrl(req, clientId);
		} else if (principal == null || principal.getExtLogin() == null || principal.getExtSourceName() == null) {
			redirectURL = this.buildAuthenticationUrl(req, clientId);
		}

		if (redirectURL != null) {
			log.debug("{} - redirecting user to URL: {}", FILTER_NAME, redirectURL);
			res.sendRedirect(redirectURL);
		} else {
			PerunUser user = null;
			if (principal == null && !UNAPPROVED.matches(req)) {
				//user is logged in, but we cannot find him in Perun
				log.warn("{} - user is logged in, no principal found. Redirect user to UNAPPROVED view.", FILTER_NAME);
				FiltersUtils.redirectUnapproved(req, res, clientId);
				return;
			} else {
				try {
					user = perunAdapter.getPreauthenticatedUserId(principal);
				} catch (RuntimeException e) {
					//user is logged in, but we cannot find him in Perun
				}
				if (user == null && !UNAPPROVED.matches(req)) {
					log.warn("{} - user is logged in, no user has been found in Perun for principal '{}'. " +
							"Redirect user to UNAPPROVED view.", FILTER_NAME, principal);
					FiltersUtils.redirectUnapproved(req, res, clientId);
					return;
				}
				if (principal != null && req.getParameter(PARAM_ACR_VALUES) != null
						&& AUTHORIZE.matches(req)) {
					storeAcr(principal, req);
				}
			}
			log.debug("{} - user '{}' is logged in, continue execution.", FILTER_NAME, user);
			super.doFilter(request, response, chain);
		}
	}

	/**
	 * Extracts extSourceName and extLogin from HTTP request.
	 *
	 * @param req HTTP request
	 * @return extracted user info as instance of PerunPrincipal
	 */
	@Override
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest req) {
		PerunPrincipal perunPrincipal = FiltersUtils.extractPerunPrincipal(req, config.getProxyExtSourceName());
		if (perunPrincipal == null) {
			String shibIdentityProvider = config.getProxyExtSourceName();
			if (shibIdentityProvider == null) {
				shibIdentityProvider = (String) req.getAttribute(SHIB_IDENTITY_PROVIDER);
			}
			String remoteUser = req.getRemoteUser();
			throw new IllegalStateException("ExtSource name or userExtSourceLogin is null: (" +
					"extSourceName: " + shibIdentityProvider + ", " +
					"extLogin: " + remoteUser + ')'
			);
		}
		return perunPrincipal;
	}

	@Override
	protected Object getPreAuthenticatedCredentials(HttpServletRequest httpServletRequest) {
		return "no credentials";
	}

	private void storeAcr(PerunPrincipal principal, HttpServletRequest req) {
		String sub = principal.getExtLogin();
		String clientId = req.getParameter(PARAM_CLIENT_ID);
		String state = req.getParameter(PARAM_STATE);
		String shibAuthnContextClass = (String) req.getAttribute(SHIB_AUTHN_CONTEXT_CLASS);
		if (shibAuthnContextClass == null) {
			shibAuthnContextClass = (String) req.getAttribute(SHIB_AUTHN_CONTEXT_METHOD);
		}
		long expiresAt = Instant.now().plusSeconds(600L).toEpochMilli();

		Acr acr = new Acr(sub, clientId, state, shibAuthnContextClass, expiresAt);
		log.trace("{} - store acr '{}'", FILTER_NAME, acr);
		acrRepository.store(acr);
	}

	private String buildLoginURL(HttpServletRequest req, String clientId, boolean forceAuthn, boolean addLoggedOut)
			throws UnsupportedEncodingException
	{
		String returnURL;
		if (addLoggedOut) {
			returnURL = FiltersUtils.buildRequestURL(req, Collections.singletonMap(PARAM_LOGGED_OUT, "true"));
		} else {
			returnURL = FiltersUtils.buildRequestURL(req);
		}
		String authnContextClassRef = buildAuthnContextClassRef(clientId, req);

		String base = config.getSamlLoginURL();
		Map<String, String> params = new HashMap<>();
		params.put(PARAM_TARGET, returnURL);

		if (authnContextClassRef != null && !authnContextClassRef.trim().isEmpty()) {
			params.put(PARAM_AUTHN_CONTEXT_CLASS_REF, authnContextClassRef);
		}
		if (forceAuthn) {
			params.put(PARAM_FORCE_AUTHN, "true");
		}

		String finalUrl = addParamsToUrl(base, params);
		log.trace("{} - buildLoginUrl: returning '{}'", FILTER_NAME, finalUrl);
		return finalUrl;
	}

	private String buildAuthnContextClassRef(String clientId, HttpServletRequest req) {
		String filterParam = constructIdpFilter(clientId, req);
		String acrValues = extractAcrValuesFromRequestParam(req);
		// temporarily, while OIDC is behind shibboleth, the AARC_IDP_HINT is passed in authnContextClassRef
		// when migrated to an embedded SAML SP, different auth or SMTH similar, it can be passed as a separate param
		String aarcIdpHint = extractAarcIdpHintFromRequestParam(req);

		StringJoiner joiner = new StringJoiner(" ");
		if (StringUtils.hasText(aarcIdpHint)) {
			try {
				joiner.add(IDP_ENTITY_ID_PREFIX + URLDecoder.decode(aarcIdpHint, StandardCharsets.UTF_8.toString()));
			} catch (UnsupportedEncodingException e) {
				//this should not happen
			}
		}

		if (StringUtils.hasText(filterParam)) {
			joiner.add(filterParam);
		}

		if (StringUtils.hasText(acrValues)) {
			String[] parts = acrValues.split(" ");
			if (parts.length > 0) {
				for (String part: parts) {
					if (StringUtils.hasText(part)) {
						joiner.add(part.trim());
					}
				}
			}
		}

		return joiner.toString().trim().isEmpty() ? null : joiner.toString();
	}

	private String addParamsToUrl(String base, Map<String, String> params) throws UnsupportedEncodingException {
		String returnUrl = base;
		if (params != null && !params.isEmpty()) {
			StringJoiner paramsJoiner = new StringJoiner("&");
			for (Map.Entry<String, String> param : params.entrySet()) {
				String paramName = param.getKey();
				String paramValue = urlEncode(param.getValue());
				paramsJoiner.add(paramName + '=' + paramValue);
			}

			returnUrl += '?' + paramsJoiner.toString();
		}
		log.trace("{} - addParamsToUrl: returning '{}'", FILTER_NAME, returnUrl);
		return returnUrl;
	}

	private String urlEncode(String str) throws UnsupportedEncodingException {
		return URLEncoder.encode(str, String.valueOf(StandardCharsets.UTF_8));
	}

	private String constructIdpFilter(String clientId, HttpServletRequest req) {
		Map<String, PerunAttributeValue> filterAttributes = Collections.emptyMap();
		String idpFilterValue = null;

		if (config.isAskPerunForIdpFiltersEnabled()) {
			Facility facility = null;
			if (clientId != null) {
				facility = perunAdapter.getFacilityByClientId(clientId);
			}
			if (facility != null) {
				filterAttributes = this.getFacilityFilterAttributes(facility);
			}
		}

		String idpEntityId = null;
		if (req.getParameter(PARAM_WAYF_IDP) != null) {
			idpEntityId = req.getParameter(PARAM_WAYF_IDP);
		}

		if (idpEntityId != null) {
			idpFilterValue = IDP_ENTITY_ID_PREFIX + idpEntityId;
		} else {
			String idpFilter = this.extractIdpFilter(req, filterAttributes);
			if (idpFilter != null) {
				idpFilterValue = FILTER_PREFIX + idpFilter;
			} else {
				String idpEFilter = this.extractIdpEFilter(req, filterAttributes);
				if (idpEFilter != null) {
					idpFilterValue = EFILTER_PREFIX + idpEFilter;
				}
			}
		}

		if (idpFilterValue != null) {
			log.debug("{} - use IDP FILTER with value '{}'", FILTER_NAME, idpFilterValue);
		} else {
			log.debug("{} - no IDP FILTER will be used", FILTER_NAME);
		}
		return idpFilterValue;
	}

	private String extractAcrValuesFromRequestParam(HttpServletRequest req) {
		String acrValues = null;
		if (req.getParameter(PARAM_ACR_VALUES) != null) {
			acrValues = req.getParameter(PARAM_ACR_VALUES);
		}

		return acrValues;
	}

	private String extractAarcIdpHintFromRequestParam(HttpServletRequest req) {
		String aarcIdpHint = null;
		if (req.getParameter(AARC_IDP_HINT) != null) {
			aarcIdpHint = req.getParameter(AARC_IDP_HINT);
		}

		return aarcIdpHint;
	}

	private String extractIdpEFilter(HttpServletRequest req, Map<String, PerunAttributeValue> filterAttributes) {
		String result = null;
		if (req.getParameter(PARAM_WAYF_EFILTER) != null) {
			result = req.getParameter(PARAM_WAYF_EFILTER);
		} else if (filterAttributes.get(facilityAttrsConfig.getWayfEFilterAttr()) != null) {
			PerunAttributeValue filterAttribute = filterAttributes.get(facilityAttrsConfig.getWayfEFilterAttr());
			if (filterAttribute != null && filterAttribute.valueAsString() != null) {
				result = filterAttribute.valueAsString();
			}
		}
		return result;
	}

	private String extractIdpFilter(HttpServletRequest req, Map<String, PerunAttributeValue> filterAttributes) {
		String result = null;
		if (req.getParameter(PARAM_WAYF_FILTER) != null) {
			result = req.getParameter(PARAM_WAYF_FILTER);
		} else if (filterAttributes.get(facilityAttrsConfig.getWayfFilterAttr()) != null) {
			PerunAttributeValue filterAttribute = filterAttributes.get(facilityAttrsConfig.getWayfFilterAttr());
			if (filterAttribute != null && filterAttribute.valueAsString() != null) {
				result = filterAttribute.valueAsString();
			}
		}

		return result;
	}

	private Map<String, PerunAttributeValue> getFacilityFilterAttributes(Facility facility) {
		if (facility != null && facility.getId() != null) {
			List<String> attrsToFetch = new ArrayList<>();
			attrsToFetch.add(facilityAttrsConfig.getWayfEFilterAttr());
			attrsToFetch.add(facilityAttrsConfig.getWayfFilterAttr());
			return perunAdapter.getFacilityAttributeValues(facility, attrsToFetch);
		}
		return new HashMap<>();
	}

	private boolean mfaRequestedAndNotPerformedYet(HttpServletRequest req) {
		return req.getParameter(PARAM_ACR_VALUES) != null
				&& req.getParameter(PARAM_ACR_VALUES).contains(REFEDS_MFA)
				&& req.getParameter(PARAM_LOGGED_OUT) == null;
	}

	private String buildMfaAuthenticationUrl(HttpServletRequest req, String clientId)
			throws UnsupportedEncodingException
	{
		log.debug("{} - MFA requested, build login URL with forced login", FILTER_NAME);
		return this.buildLoginURL(req, clientId, true, true);
	}

	private String buildForceAuthenticationUrl(HttpServletRequest req, String clientId)
			throws UnsupportedEncodingException
	{
		log.debug("{} - build login URL with forced login", FILTER_NAME);
		return this.buildLoginURL(req, clientId, true, false);
	}

	private String buildAuthenticationUrl(HttpServletRequest req, String clientId)
			throws UnsupportedEncodingException
	{
		log.debug("{} - build login URL with no additional params", FILTER_NAME);
		return this.buildLoginURL(req, clientId, false, false);
	}

}
