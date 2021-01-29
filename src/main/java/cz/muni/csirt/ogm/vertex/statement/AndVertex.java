package cz.muni.csirt.ogm.vertex.statement;

import cz.muni.csirt.nvd.cpe.transform.statement.element.And;
import cz.muni.csirt.nvd.cpe.transform.statement.element.Or;
import cz.muni.csirt.ogm.ScopedGraph;
import cz.muni.csirt.ogm.vertex.base.UnscopedVertex;

import java.util.List;

public class AndVertex extends UnscopedVertex<And> {

    public List<? extends OrVertex> getOrOperands() {
        return traverse(v -> v.out("hasOrOperand")).toList(OrVertex.class);
    }

    public void addOrOperand(OrVertex vertex) {
        linkOut(vertex, "hasOrOperand");
    }

    @Override
    public void initialize(And dto, ScopedGraph sg) {
        for (Or orOperand : dto.getOrOperands()) {
            addOrOperand(sg.createUnscopedV(orOperand, OrVertex.class));
        }
    }
}
