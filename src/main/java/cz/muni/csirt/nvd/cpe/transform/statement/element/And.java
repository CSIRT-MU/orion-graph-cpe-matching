package cz.muni.csirt.nvd.cpe.transform.statement.element;

import java.util.List;

public class And {

    private final List<Or> orOperands;

    public And(List<Or> orOperands) {
        this.orOperands = orOperands;
    }

    public List<Or> getOrOperands() {
        return orOperands;
    }
}
