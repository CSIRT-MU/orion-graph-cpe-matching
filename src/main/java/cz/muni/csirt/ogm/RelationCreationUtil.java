package cz.muni.csirt.ogm;

import cz.muni.csirt.nvd.cpe.ReferenceImplAccess;
import cz.muni.csirt.nvd.cpe.transform.wfn.AVPair;
import cz.muni.csirt.nvd.cpe.transform.wfn.AVPairType;
import cz.muni.csirt.nvd.cpe.transform.wfn.StringRange;
import cz.muni.csirt.nvd.cpe.transform.wfn.StringRangeUtil;
import cz.muni.csirt.ogm.edge.RelationEdge;
import cz.muni.csirt.ogm.vertex.wfn.SourceAVSpecVertex;
import cz.muni.csirt.ogm.vertex.wfn.TargetAVSpecVertex;
import gov.nist.secauto.cpe.common.WellFormedName;
import gov.nist.secauto.cpe.matching.Relation;

import java.util.List;
import java.util.Optional;

public class RelationCreationUtil {

	// Call only once on SourceAVSpecVertex creation!
	public static void handleAVSpecVertexCreation(SourceAVSpecVertex source, ScopedGraph sg) {
		List<? extends TargetAVSpecVertex> targets = sg.findAllVByProperty("attribute", source.getAttribute().toString(), TargetAVSpecVertex.class);
		for (TargetAVSpecVertex target : targets) {
			RelationEdge r = source.addRelationEdge(target);
			r.setRelation(compare(source, target));
		}
	}

	// Call only once on TargetAVSpecVertex creation!
	public static void handleAVSpecVertexCreation(TargetAVSpecVertex target, ScopedGraph sg) {
		List<? extends SourceAVSpecVertex> sources = sg.findAllVByProperty("attribute", target.getAttribute().toString(), SourceAVSpecVertex.class);
		for (SourceAVSpecVertex source : sources) {
			RelationEdge r = target.addRelationEdge(source);
			r.setRelation(compare(source, target));
		}
	}

	private static Relation compare(SourceAVSpecVertex source, TargetAVSpecVertex target) {
		AVPair sourcePair = source.getAVPair();
		AVPair targetPair = target.getAVPair();

		if (sourcePair.getAttribute() != targetPair.getAttribute()) {
			throw new IllegalStateException("The AVPair attribute names do not match!");
		}

		Relation relation = ReferenceImplAccess.compare(sourcePair.getValueForComparison(), targetPair.getValueForComparison());

		if (sourcePair.getAttribute() == WellFormedName.Attribute.VERSION) {
			if ((sourcePair.getType() == AVPairType.ANY) && (targetPair.getType() == AVPairType.VALUE) && relation == Relation.SUPERSET) {
				StringRange versionStringRange = Optional
						.ofNullable(source.getStringRange())
						.orElseThrow(() -> new IllegalStateException("The versionStringRange is null for VERSION attribute."));

				boolean isInRange = StringRangeUtil
						.inRange((String) targetPair.getValueForComparison(), versionStringRange);

				if (isInRange) {
					return relation; // Relation.SUPERSET
				} else {
					return Relation.UNDEFINED; // Relation.DISJOINT is certainly less suitable. In spec, `ANY` vs. `m + wild cards` is also considered Relation.UNDEFINED.
				}
			}
			return relation;
		}

		return relation;
	}
}
