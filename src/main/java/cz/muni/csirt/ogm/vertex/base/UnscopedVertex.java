package cz.muni.csirt.ogm.vertex.base;

import cz.muni.csirt.ogm.ScopedGraph;

public abstract class UnscopedVertex<T> extends AutoJSONVertex {

    public abstract void initialize(T dto, ScopedGraph sg);
}
