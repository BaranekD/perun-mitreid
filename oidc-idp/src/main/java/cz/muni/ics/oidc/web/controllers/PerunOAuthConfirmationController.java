package cz.muni.ics.oidc.web.controllers;


import com.google.common.collect.Sets;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import cz.muni.ics.oidc.server.PerunScopeClaimTranslationService;
import cz.muni.ics.oidc.server.configurations.PerunOidcConfig;
import cz.muni.ics.oidc.server.userInfo.PerunUserInfo;
import cz.muni.ics.oidc.web.WebHtmlClasses;
import cz.muni.ics.oidc.web.langs.Localization;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.oauth2.web.OAuthConfirmationController;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.UserInfoService;
import org.mitre.openid.connect.view.HttpCodeView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Controller of the pages where user accepts that information
 * about him will be sent to the client.
 *
 * @author Dominik František Bučík <bucik@ics.muni.cz>
 * @author Peter Jancus <jancus@ics.muni.cz>
 */
@Controller
@SessionAttributes("authorizationRequest")
public class PerunOAuthConfirmationController{

    private final static Logger log = LoggerFactory.getLogger(PerunOAuthConfirmationController.class);

    @Autowired
    private OAuthConfirmationController oAuthConfirmationController;

    @Autowired
    private ClientDetailsEntityService clientService;

    @Autowired
    private UserInfoService userInfoService;

    @Autowired
    private PerunOidcConfig perunOidcConfig;

    @Autowired
    private SystemScopeService scopeService;

    @Autowired
    private PerunScopeClaimTranslationService scopeClaimTranslationService;

    @Autowired
    private Localization localization;

    @Autowired
    private WebHtmlClasses htmlClasses;

    @RequestMapping(value = "/oauth/confirm_access", params = { "client_id" })
    public String confirmAccess(Map<String, Object> model, HttpServletRequest req, Principal p,
                                @ModelAttribute("authorizationRequest") AuthorizationRequest authRequest) {
        ClientDetailsEntity client;

        try {
            client = clientService.loadClientByClientId(authRequest.getClientId());
        } catch (OAuth2Exception e) {
            log.error("confirmAccess: OAuth2Exception was thrown when attempting to load client", e);
            model.put(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
            return HttpCodeView.VIEWNAME;
        } catch (IllegalArgumentException e) {
            log.error("confirmAccess: IllegalArgumentException was thrown when attempting to load client", e);
            model.put(HttpCodeView.CODE, HttpStatus.BAD_REQUEST);
            return HttpCodeView.VIEWNAME;
        }

        if (client == null) {
            log.error("confirmAccess: could not find client " + authRequest.getClientId());
            model.put(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
            return HttpCodeView.VIEWNAME;
        }

        model.put("client", client);

        //get result
        String result = oAuthConfirmationController.confimAccess(model, authRequest, p);

        //prepare scopes in our way
        PerunUserInfo user = (PerunUserInfo) userInfoService.getByUsernameAndClientId(p.getName(),client.getClientId());
        ControllerUtils.setPageOptions(model, req, localization, htmlClasses, perunOidcConfig);
        setScopesAndClaims(model, authRequest, user);

        if (result.equals("approve") && perunOidcConfig.getTheme().equalsIgnoreCase("default")) {
            return "approve";
        } else if (result.equals("approve")) {
            model.put("page", "consent");
            return "themedApprove";
        }

        return result;
    }

    private void setScopesAndClaims(Map<String, Object> model, AuthorizationRequest authRequest, UserInfo user) {
        Set<SystemScope> scopes = scopeService.fromStrings(authRequest.getScope());
        Set<SystemScope> sortedScopes = new LinkedHashSet<>(scopes.size());
        Set<SystemScope> systemScopes = scopeService.getAll();

        // sort scopes for display based on the inherent order of system scopes
        for (SystemScope s : systemScopes) {
            if (scopes.contains(s)) {
                sortedScopes.add(s);
            }
        }

        // add in any scopes that aren't system scopes to the end of the list
        sortedScopes.addAll(Sets.difference(scopes, systemScopes));

        Map<String, Map<String, Object>> claimsForScopes = new LinkedHashMap<>();
        if (user != null) {
            JsonObject userJson = user.toJson();
            for (SystemScope systemScope : sortedScopes) {
                Map<String, Object> claimValues = new LinkedHashMap<>();
                Set<String> claims = scopeClaimTranslationService.getClaimsForScope(systemScope.getValue());
                for (String claim : claims) {
                    if (userJson.has(claim)) {
                        JsonElement claimJson = userJson.get(claim);
                        if (claimJson == null || claimJson.isJsonNull()) {
                            continue;
                        }
                        if (claimJson.isJsonPrimitive()) {
                            claimValues.put(claim, claimJson.getAsString());
                        } else if (claimJson.isJsonArray()) {
                            JsonArray arr = userJson.getAsJsonArray(claim);
                            List<String> values = new ArrayList<>();
                            for (int i = 0; i < arr.size(); i++) {
                                values.add(arr.get(i).getAsString());
                            }
                            claimValues.put(claim, values);
                        }
                    }
                }
                if (!claimValues.isEmpty()) {
                    claimsForScopes.put(systemScope.getValue(), claimValues);
                }
            }
        }

        sortedScopes = sortedScopes.stream()
                .filter(systemScope -> {
                    if ("offline_access".equalsIgnoreCase(systemScope.getValue())) {
                        claimsForScopes.put("offline_access", Collections.singletonMap("offline_access", true));
                        return true;
                    }
                    return claimsForScopes.containsKey(systemScope.getValue());
                })
                .collect(Collectors.toSet());
        model.put("claims", claimsForScopes);
        model.put("scopes", sortedScopes);
    }

}
