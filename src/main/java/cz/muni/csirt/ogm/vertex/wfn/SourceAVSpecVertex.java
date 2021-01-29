package cz.muni.csirt.ogm.vertex.wfn;

import cz.muni.csirt.nvd.cpe.transform.wfn.AVPair;
import cz.muni.csirt.nvd.cpe.transform.wfn.SourceAVSpec;
import cz.muni.csirt.nvd.cpe.transform.wfn.StringRange;
import cz.muni.csirt.ogm.AVSpecVertexWithAttribute;
import cz.muni.csirt.ogm.RelationCreationUtil;
import cz.muni.csirt.ogm.ScopedGraph;
import cz.muni.csirt.ogm.edge.RelationEdge;
import cz.muni.csirt.ogm.vertex.base.ScopedVertex;
import gov.nist.secauto.cpe.common.WellFormedName;

import java.util.List;

public class SourceAVSpecVertex extends ScopedVertex<SourceAVSpec> implements AVSpecVertexWithAttribute {

    public WellFormedName.Attribute getAttribute() {
        return WellFormedName.Attribute.valueOf(getProperty("attribute"));
    }

    public void setAttribute(WellFormedName.Attribute attribute) {
        setProperty("attribute", attribute.toString());
    }

    public AVPair getAVPair() {
        return getJSONProperty("avPair", AVPair.class);
    }

    public void setAVPair(AVPair avPair) {
        setJSONProperty("avPair", avPair);
    }

    public StringRange getStringRange() {
        return getJSONProperty("stringRange", StringRange.class);
    }

    public void setStringRange(StringRange stringRange) {
        setJSONProperty("stringRange", stringRange);
    }

    public RelationEdge addRelationEdge(TargetAVSpecVertex vertex) {
        return addFramedEdge("hasRelation", vertex, RelationEdge.class);
    }

    public List<? extends RelationEdge> getRelationEdges() {
        return traverse(t -> t.bothE("hasRelation")).toList(RelationEdge.class);
    }

    @Override
    public String extractUid(SourceAVSpec dto) {
        return dto.toString();
    }

    @Override
    public void initialize(SourceAVSpec dto, ScopedGraph sg) {
        setAttribute(dto.getAVPair().getAttribute());
        setAVPair(dto.getAVPair());
        setStringRange(dto.getStringRange()); // stringRange is not null only for WellFormedName.Attribute.VERSION
        RelationCreationUtil.handleAVSpecVertexCreation(this, sg);
    }
}
