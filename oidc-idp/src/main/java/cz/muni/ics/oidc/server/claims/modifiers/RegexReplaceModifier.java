package cz.muni.ics.oidc.server.claims.modifiers;

import cz.muni.ics.oidc.server.claims.ClaimModifier;
import cz.muni.ics.oidc.server.claims.ClaimModifierInitContext;

import java.util.regex.Pattern;

/**
 * Replace regex modifier. Replaces parts matched by regex with string using backreferences to groups.
 * <ul>
 *     <li><b>custom.claim.[claimName].modifier.find</b> - string to be replaced, can be a regex</li>
 *     <li><b>custom.claim.[claimName].modifier.append</b> - string to be used as replacement</li>
 * </ul>
 *
 * @see java.util.regex.Matcher#replaceAll(String)
 * @author Martin Kuba <makub@ics.muni.cz>
 */
@SuppressWarnings("unused")
public class RegexReplaceModifier extends ClaimModifier {

	private static final String FIND = "find";
	private static final String REPLACE = "replace";

	private final Pattern regex;
	private final String replacement;

	public RegexReplaceModifier(ClaimModifierInitContext ctx) {
		super(ctx);
		regex = Pattern.compile(ctx.getProperty(FIND, ""));
		replacement = ctx.getProperty(REPLACE, "");
	}

	@Override
	public String modify(String value) {
		return regex.matcher(value).replaceAll(replacement);
	}

	@Override
	public String toString() {
		return "RegexReplaceModifier replacing" + regex.pattern() + " with " + replacement;
	}
}
