package cz.muni.csirt.nvd.cpe.transform.statement.element;

import gov.nist.nvd.feed.cve.DefCpeMatch;

public class FactRef {

    private final DefCpeMatch cpeMatch;

    public FactRef(DefCpeMatch cpeMatch) {
        this.cpeMatch = cpeMatch;
    }

    public DefCpeMatch getCpeMatch() {
        return cpeMatch;
    }
}
