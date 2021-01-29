package cz.muni.csirt.matching;

import cz.muni.csirt.ogm.ScopedGraph;
import cz.muni.csirt.ogm.vertex.CveVertex;
import cz.muni.csirt.ogm.vertex.asset.AssetVertex;
import gov.nist.secauto.cpe.common.WellFormedName;
import gov.nist.secauto.cpe.matching.Relation;
import org.apache.tinkerpop.gremlin.process.traversal.P;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversal;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.__;
import org.apache.tinkerpop.gremlin.structure.Column;
import org.apache.tinkerpop.gremlin.structure.Vertex;

import java.util.*;
import java.util.stream.Collectors;

import static org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.__.*;

public class CpeGraphMatcher {

    public static final List<Relation> SUPERSET_OR_EQUAL = Arrays.asList(Relation.EQUAL, Relation.SUPERSET);
    public static final P<Object> ALL_IDS_PREDICATE = P.without(Collections.emptyList());

    private final ScopedGraph scopedGraph;

    public CpeGraphMatcher(ScopedGraph scopedGraph) {
        this.scopedGraph = scopedGraph;
    }

    public List<Map<String, Object>> findByCve(String uid) {
        Optional<CveVertex> v = scopedGraph.findVByUid(uid, CveVertex.class);

        if (v.isEmpty()) {
            return Collections.emptyList();
        }

        return findAll(SUPERSET_OR_EQUAL, P.eq(v.get().getId()), ALL_IDS_PREDICATE);
    }

    public List<Map<String, Object>> findByAsset(String uid) {
        Optional<AssetVertex> v = scopedGraph.findVByUid(uid, AssetVertex.class);

        if (v.isEmpty()) {
            return Collections.emptyList();
        }

        return findAll(SUPERSET_OR_EQUAL, ALL_IDS_PREDICATE, P.eq(v.get().getId()));
    }

    public List<Map<String, Object>> findAll() {
        return findAll(SUPERSET_OR_EQUAL, ALL_IDS_PREDICATE, ALL_IDS_PREDICATE);
    }

    public List<Map<String, Object>> findAll(List<Relation> allowedRelations, P<Object> cveIdFilter, P<Object> assetIdFilter) {
        GraphTraversal<Vertex, Long> hasSomeParent = outE("hasParent")
                .count()
                .is(0);

        GraphTraversal<Vertex, Vertex> optionalParentTraversal = repeat(out("hasParent"))
                .until(hasSomeParent);

        GraphTraversal<Object, Long> expectedAndOperandsCount = select(Column.keys)
                .select("x_Statement")
                .out("hasAndOperand")
                .count();

        GraphTraversal<Object, Long> actualAndOperandsCount = select(Column.values)
                .unfold()
                .select("x_Or")
                .dedup()
                .in("hasOrOperand")
                .dedup()
                .count();

        /* Traversal from FactRef to AssetCPE, which has at least ONE Relation between
         * SourceAVSpec-TargetAVSpec set to ANY type that IS NOT allowed.
         * */
        GraphTraversal<Vertex, Vertex> negateTrue = out("hasFactRef") // FactRef
                .as("x_FactRef")
                .out("hasSourceAVSpec") // SourceAVSpec
                .bothE("hasRelation") // RelationEdge
                .has("relation", P.without(allowedRelations))
                .outV() // TargetAVSpec
                .in("hasTargetAVSpec"); // AssetCPE

        /* Traversal from FactRef to AssetCPE, which has ALL the Relations between
         * SourceAVSpec-TargetAVSpec set to ANY type that IS allowed.
         * */
        GraphTraversal<Vertex, Vertex> negateFalse = out("hasFactRef") // FactRef
                .match(attributesMatch(allowedRelations))
                .select("x_Single_Vertex_Match"); // AssetCPE


        List<Map<String, Object>> result = scopedGraph.V(CveVertex.class)
                .getRawTraversal()
                .hasId(cveIdFilter)
                .as("x_Cve")
                .out("hasStatement")
                .as("x_Statement")
                .out("hasAndOperand")
                .out("hasOrOperand")
                .as("x_Or")
                .choose(has("negate", false), negateFalse, negateTrue)
                .as("x_AssetCPE")
                .dedup("x_FactRef", "x_AssetCPE")
                .out("classifies") // AssetVertex
                .optional(optionalParentTraversal)
                .hasId(assetIdFilter)
                .as("x_RootAsset")
                .group()
                .by(select("x_Cve", "x_Statement", "x_RootAsset"))
                .by(select("x_Or", "x_FactRef", "x_AssetCPE").fold())
                .unfold()
                .project("match", "path", "expectedCount", "actualCount")
                .by(select(Column.keys))
                .by(select(Column.values))
                .by(expectedAndOperandsCount)
                .by(actualAndOperandsCount)
                .where("expectedCount", P.eq("actualCount"))
                .toList();

        return result;
    }

    private GraphTraversal<Object, Vertex> attributeTraversal(WellFormedName.Attribute attribute, String[] relations) {
        return __.as("x_FactRef")
                .out("hasSourceAVSpec")
                .has("attribute", attribute.toString())
                .bothE("hasRelation")
                .has("relation", P.within(relations))
                .outV()
                .in("hasTargetAVSpec")
                .as("x_Single_Vertex_Match");
    }

    @SuppressWarnings("rawtypes")
    private GraphTraversal[] attributesMatch(List<Relation> allowedRelations) {
        WellFormedName.Attribute[] attributes = WellFormedName.Attribute.values();

        String[] relations = allowedRelations
                .stream()
                .map(Enum::toString)
                .collect(Collectors.toList())
                .toArray(new String[allowedRelations.size()]);

        return Arrays
                .stream(attributes)
                .map(a -> attributeTraversal(a, relations))
                .collect(Collectors.toList())
                .toArray(new GraphTraversal[attributes.length]);
    }
}
