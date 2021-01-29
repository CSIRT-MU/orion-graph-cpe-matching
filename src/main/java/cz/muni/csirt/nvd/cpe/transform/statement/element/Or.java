package cz.muni.csirt.nvd.cpe.transform.statement.element;

public class Or {

    private final boolean negate;
    private final FactRef factRef;

    public Or(boolean negate, FactRef factRef) {
        this.negate = negate;
        this.factRef = factRef;
    }

    public boolean isNegate() {
        return negate;
    }

    public FactRef getFactRef() {
        return factRef;
    }
}
