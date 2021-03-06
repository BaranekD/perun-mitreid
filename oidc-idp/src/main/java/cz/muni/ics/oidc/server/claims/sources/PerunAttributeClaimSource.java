package cz.muni.ics.oidc.server.claims.sources;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.NullNode;
import cz.muni.ics.oidc.server.claims.ClaimSource;
import cz.muni.ics.oidc.server.claims.ClaimSourceInitContext;
import cz.muni.ics.oidc.server.claims.ClaimSourceProduceContext;
import cz.muni.ics.oidc.server.claims.ClaimUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Source for claim which get value of attribute from Perun.
 *
 * Configuration (replace [claimName] with the name of the claim):
 * <ul>
 *     <li><b>custom.claim.[claimName].source.attribute</b> - name of the attribute in Perun</li>
 * </ul>
 *
 * @author Martin Kuba <makub@ics.muni.cz>
 * @author Dominik Frantisek Bucik <bucik@ics.muni.cz>
 */
@SuppressWarnings("unused")
public class PerunAttributeClaimSource extends ClaimSource {

	public static final Logger log = LoggerFactory.getLogger(PerunAttributeClaimSource.class);

	private static final String ATTRIBUTE = "attribute";

	private final String attributeName;

	public PerunAttributeClaimSource(ClaimSourceInitContext ctx) {
		super(ctx);
		this.attributeName = ClaimUtils.fillStringPropertyOrNoVal(ATTRIBUTE, ctx);
		if (!ClaimUtils.isPropSet(this.attributeName)) {
			throw new IllegalArgumentException("Missing mandatory configuration option - attribute");
		}
	}

	@Override
	public JsonNode produceValue(ClaimSourceProduceContext pctx) {
		JsonNode value = NullNode.getInstance();
		if (ClaimUtils.isPropSetAndHasAttribute(attributeName, pctx)) {
			value = pctx.getAttrValues().get(attributeName).valueAsJson();
		}

		log.debug("Produced value for attribute {}: {}", attributeName, value);
		return value;
	}

	@Override
	public String toString() {
		return "Perun attribute " + attributeName;
	}

}
