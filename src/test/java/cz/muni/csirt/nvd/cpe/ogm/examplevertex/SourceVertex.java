package cz.muni.csirt.nvd.cpe.ogm.examplevertex;

import cz.muni.csirt.ogm.ScopedGraph;
import cz.muni.csirt.ogm.vertex.base.ScopedVertex;

public class SourceVertex extends ScopedVertex<String> {

    public String getName() {
        return getProperty("name");
    }

    public void setName(String name) {
        setProperty("name", name);
    }

    @Override
    public String extractUid(String dto) {
        return dto;
    }

    @Override
    public void initialize(String dto, ScopedGraph sg) {
    }
}
