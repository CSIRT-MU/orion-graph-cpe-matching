package cz.muni.csirt.ogm.vertex.statement;

import cz.muni.csirt.nvd.cpe.transform.statement.StatementCNF;
import cz.muni.csirt.nvd.cpe.transform.statement.element.And;
import cz.muni.csirt.ogm.ScopedGraph;
import cz.muni.csirt.ogm.vertex.base.UnscopedVertex;
import gov.nist.nvd.feed.cve.DefNode;

import java.util.List;

public class StatementVertex extends UnscopedVertex<StatementCNF> {

    public List<? extends AndVertex> getAndOperands() {
        return traverse(v -> v.out("hasAndOperand")).toList(AndVertex.class);
    }

    public void addAndOperand(AndVertex vertex) {
        linkOut(vertex, "hasAndOperand");
    }

    public DefNode getDefNode() {
        return getJSONProperty("defNode", DefNode.class);
    }

    public void setDefNode(DefNode defNode) {
        setJSONProperty("defNode", defNode);
    }

    @Override
    public void initialize(StatementCNF dto, ScopedGraph sg) {
        for (And andOperand : dto.getAndOperands()) {
            addAndOperand(sg.createUnscopedV(andOperand, AndVertex.class));
        }
        setDefNode(dto.getDefNode());
    }
}
