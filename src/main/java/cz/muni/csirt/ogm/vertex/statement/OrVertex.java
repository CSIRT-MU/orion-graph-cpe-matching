package cz.muni.csirt.ogm.vertex.statement;

import cz.muni.csirt.nvd.cpe.transform.statement.element.Or;
import cz.muni.csirt.ogm.ScopedGraph;
import cz.muni.csirt.ogm.vertex.base.UnscopedVertex;

public class OrVertex extends UnscopedVertex<Or> {

    public boolean getNegate() {
        return getProperty("negate");
    }

    public void setNegate(boolean negate) {
        setProperty("negate", negate);
    }

    public FactRefVertex getFactRef() {
        return traverse(v -> v.out("hasFactRef")).next(FactRefVertex.class);
    }

    public void setFactRef(FactRefVertex vertex) {
        setLinkOut(vertex, "hasFactRef");
    }

    @Override
    public void initialize(Or dto, ScopedGraph sg) {
        setNegate(dto.isNegate());
        setFactRef(sg.createUnscopedV(dto.getFactRef(), FactRefVertex.class));
    }
}
