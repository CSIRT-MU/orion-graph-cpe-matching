package cz.muni.csirt.nvd.cpe.ogm.examplevertex;

import cz.muni.csirt.ogm.ScopedGraph;
import cz.muni.csirt.ogm.vertex.base.ScopedVertex;

public class AlertVertex extends ScopedVertex<String> {

    public Integer getSeverity() {
        return getProperty("severity");
    }

    public void setSeverity(Integer severity) {
        setProperty("severity", severity);
    }

    @Override
    public String extractUid(String dto) {
        return dto;
    }

    @Override
    public void initialize(String dto, ScopedGraph sg) {
    }
}
