package cz.muni.csirt.nvd.cpe.ogm;

import com.syncleus.ferma.DelegatingFramedGraph;
import com.syncleus.ferma.FramedGraph;
import cz.muni.csirt.nvd.cpe.ogm.examplevertex.AlertVertex;
import cz.muni.csirt.nvd.cpe.ogm.examplevertex.AnotherVertex;
import cz.muni.csirt.nvd.cpe.ogm.examplevertex.SourceVertex;
import cz.muni.csirt.ogm.ScopedGraph;
import org.apache.tinkerpop.gremlin.structure.Graph;
import org.apache.tinkerpop.gremlin.tinkergraph.structure.TinkerGraph;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class ScopedGraphTest {

    @Test
    public void testScopedMode() {
        final String uid1 = "7ca44";
        final String uid2 = "fg19e";

        Graph graph = TinkerGraph.open();

        // implies annotated mode
        FramedGraph fg = new DelegatingFramedGraph<>(graph, true, false);
        ScopedGraph sg = new ScopedGraph(fg);

        AlertVertex v1 = sg.getOrCreateV(uid1, AlertVertex.class);
        v1.setSeverity(5);

        assertTrue(sg.existsV(uid1, AlertVertex.class));
        assertFalse(sg.existsV(uid2, SourceVertex.class));

        SourceVertex v2 = sg.createV(uid2, SourceVertex.class);
        v2.setName("flows:ics:ol:14");

        assertTrue(sg.existsV(uid2, SourceVertex.class));

        SourceVertex v3 = sg.getOrCreateV(uid2, SourceVertex.class);
        assertEquals("flows:ics:ol:14", v3.getName());

        assertFalse(sg.existsV(uid1, SourceVertex.class));
        assertFalse(sg.existsV(uid2, AlertVertex.class));

        assertFalse(sg.existsV(uid1, AnotherVertex.class));
        assertFalse(sg.existsV(uid2, AnotherVertex.class));

        // The vertices are queried without scoping their class, so if other uids were present that
        // were equal, multiple vertices would be returned. Always scope the class in queries.
        AlertVertex r1 = fg.traverse((g) -> g.V().has("uid", uid1)).next(AlertVertex.class);
        SourceVertex r2 = fg.traverse((g) -> g.V().has("uid", uid2)).next(SourceVertex.class);

        List<? extends AlertVertex> l1 = sg.findAllVByProperty("uid", uid1, AlertVertex.class);
        assertEquals(1, l1.size());
        assertEquals((Long) r1.getId(), l1.get(0).getId());

        Optional<AlertVertex> r3 = sg.findV("00000", AlertVertex.class);
        assertNull(r3.orElse(null));

        AlertVertex r4 = sg.findV(uid1, AlertVertex.class).orElseThrow();
        assertEquals(5, r4.getSeverity());

        assertEquals((Long) v2.getId(), v3.getId());
        assertEquals((Long) v1.getId(), r1.getId());
        assertEquals((Long) v2.getId(), r2.getId());
        assertEquals((Long) v1.getId(), r4.getId());

        assertTrue(AlertVertex.class.isAssignableFrom(r1.getClass()));
        assertTrue(SourceVertex.class.isAssignableFrom(r2.getClass()));
    }
}
