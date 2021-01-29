package cz.muni.csirt.ogm;

import com.syncleus.ferma.FramedGraph;
import com.syncleus.ferma.Traversable;
import com.syncleus.ferma.typeresolvers.TypeResolver;
import cz.muni.csirt.ogm.vertex.base.ScopedVertex;
import cz.muni.csirt.ogm.vertex.base.UnscopedVertex;

import java.util.List;
import java.util.Optional;

public class ScopedGraph {

    private final FramedGraph framedGraph;

    public ScopedGraph(FramedGraph framedGraph) {
        this.framedGraph = framedGraph;
    }

    public <T, X extends UnscopedVertex<T>> X createUnscopedV(T dto, Class<X> aClass) {
        X vertex = framedGraph.addFramedVertex(aClass);
        vertex.initialize(dto, this);
        return vertex;
    }

    public <T, X extends ScopedVertex<T>> X createV(T dto, Class<X> aClass) {
        X vertex = createUnscopedV(dto, aClass);
        vertex.setUid(extractUid(dto, aClass));
        return vertex;
    }

    public <T, X extends ScopedVertex<T>> X getOrCreateV(T dto, Class<X> aClass) {
        return findV(dto, aClass).orElseGet(() -> createV(dto, aClass));
    }

    public <T, X extends ScopedVertex<T>> boolean existsV(T dto, Class<X> aClass) {
        return existsVByUid(extractUid(dto, aClass), aClass);
    }

    public <T, X extends ScopedVertex<T>> boolean existsVByUid(String uid, Class<X> aClass) {
        return findVByUid(uid, aClass).isPresent();
    }

    public <T, X extends ScopedVertex<T>> Optional<X> findV(T dto, Class<X> aClass) {
        return findVByUid(extractUid(dto, aClass), aClass);
    }

    public <T, X extends ScopedVertex<T>> Optional<X> findVByUid(String uid, Class<X> aClass) {
        X x = V(aClass)
              .traverse(t -> t.has(ScopedVertex.UID_ATTR, uid))
              .nextOrDefault(aClass, null);

        return Optional.ofNullable(x);
    }

    public <T, X extends UnscopedVertex<T>> List<? extends X> findAllVByProperty(String propertyKey, Object value, Class<X> aClass) {
        return V(aClass)
              .traverse(t -> t.has(propertyKey, value))
              .toList(aClass);
    }

    public <T, X extends UnscopedVertex<T>> List<? extends X> findAllV(Class<X> aClass) {
        return V(aClass).toList(aClass);
    }

    public <X> Traversable<?, ?> V(Class<X> aClass) {
        TypeResolver tr = framedGraph.getTypeResolver();
        return framedGraph.traverse(g -> tr.hasType(g.V(), aClass));
    }

    public static <T, X extends ScopedVertex<T>> String extractUid(T dto, Class<X> aClass) {
        try {
            return aClass.getDeclaredConstructor().newInstance().extractUid(dto);
        } catch (ReflectiveOperationException e) {
            throw new IllegalArgumentException(String
                    .format("Reflective access failed for default constructor. class=%s", aClass.getCanonicalName()), e);
        }
    }
}
