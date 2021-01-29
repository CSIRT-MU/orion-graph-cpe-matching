package cz.muni.csirt.nvd.cpe.transform.statement;

import cz.muni.csirt.nvd.cpe.transform.statement.element.And;
import gov.nist.nvd.feed.cve.DefNode;

import java.util.List;

public class StatementCNF {

    private final List<And> andOperands;
    private final DefNode defNode;

    public StatementCNF(List<And> andOperands, DefNode defNode) {
        this.andOperands = andOperands;
        this.defNode = defNode;
    }

    public List<And> getAndOperands() {
        return andOperands;
    }

    public DefNode getDefNode() {
        return defNode;
    }
}
