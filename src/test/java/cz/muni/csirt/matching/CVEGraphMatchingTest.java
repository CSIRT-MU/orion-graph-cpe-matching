package cz.muni.csirt.matching;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.syncleus.ferma.DelegatingFramedGraph;
import com.syncleus.ferma.FramedGraph;
import cz.muni.csirt.asset.SimpleAsset;
import cz.muni.csirt.ogm.ScopedGraph;
import cz.muni.csirt.ogm.vertex.CveVertex;
import cz.muni.csirt.ogm.vertex.asset.AssetCPEVertex;
import cz.muni.csirt.ogm.vertex.asset.AssetVertex;
import cz.muni.csirt.ogm.vertex.base.ScopedVertex;
import cz.muni.csirt.ogm.vertex.statement.StatementVertex;
import cz.muni.csirt.ogm.vertex.wfn.SourceAVSpecVertex;
import cz.muni.csirt.ogm.vertex.wfn.TargetAVSpecVertex;
import gov.nist.nvd.feed.cve.DefCveItem;
import gov.nist.secauto.cpe.common.WellFormedName;
import org.apache.tinkerpop.gremlin.process.traversal.P;
import org.apache.tinkerpop.gremlin.structure.Graph;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import org.apache.tinkerpop.gremlin.tinkergraph.structure.TinkerGraph;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

public class CVEGraphMatchingTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private List<SimpleAsset> assetList;

    @BeforeEach
    void setUp() throws IOException {
        Path path = Paths.get("src", "test", "resources", "assets", "cve", "assets.json");
        CollectionType type = OBJECT_MAPPER.getTypeFactory().constructCollectionType(ArrayList.class, SimpleAsset.class);
        assetList = OBJECT_MAPPER.readValue(Files.readString(path), type);
    }

    @Test
    public void testWithTinkerGraph() throws IOException {
        Path path = Paths.get("src", "test", "resources", "assets", "cve", "entries", "nvdentry3.json");
        DefCveItem cveItem = OBJECT_MAPPER.readValue(path.toFile(), DefCveItem.class);

        Graph graph = TinkerGraph.open();
        FramedGraph fg = new DelegatingFramedGraph<>(graph, true, false);
        ScopedGraph sg = new ScopedGraph(fg);
        CpeGraphMatcher cgm = new CpeGraphMatcher(sg);

        CveVertex cveVertex = sg.createV(cveItem, CveVertex.class);

        assertNotEquals(cveVertex.getId(), cveVertex.getUid());

        assertTrue(sg.existsV(cveItem, CveVertex.class));

        List<? extends StatementVertex> statements = cveVertex.getStatements();
        assertEquals(1, statements.size());

        StatementVertex c = statements.get(0);
        assertEquals("OR", c.getDefNode().getOperator());

        assertEquals("4.0", cveVertex.getConfigurations().getCVEDataVersion());

        SourceAVSpecVertex specVertex = cveVertex
                .getStatements()
                .get(0)
                .getAndOperands()
                .get(0)
                .getOrOperands()
                .get(0)
                .getFactRef()
                .getSourceAVSpecs()
                .stream()
                .min(Comparator.comparing(ScopedVertex::getUid))
                .orElseThrow();

        assertEquals(WellFormedName.Attribute.EDITION, specVertex.getAVPair().getAttribute());
        assertNull(specVertex.getStringRange());

        List<? extends SourceAVSpecVertex> specVertices = sg
                .findAllVByProperty("attribute", WellFormedName.Attribute.EDITION.toString(), SourceAVSpecVertex.class);

        assertEquals(1, specVertices.size());
        assertEquals((Long) specVertex.getId(), specVertices.get(0).getId());

        assertEquals(0, sg.findAllVByProperty("attribute", WellFormedName.Attribute.VENDOR.toString(), TargetAVSpecVertex.class).size());

        assertEquals(2, sg.findAllVByProperty("attribute", WellFormedName.Attribute.PART.toString(), SourceAVSpecVertex.class).size());

        List<AssetVertex> assetVertices = assetList
                .stream()
                .map(a -> sg.createV(a, AssetVertex.class))
                .collect(Collectors.toList());

        AssetCPEVertex assetCPE = assetVertices.get(1).getAssetCPE();

        List<? extends TargetAVSpecVertex> targetAVSpecs = assetCPE.getTargetAVSpecs();

        assertEquals(11, targetAVSpecs.size());

        for (TargetAVSpecVertex targetAVSpec : targetAVSpecs) {
            assertFalse(targetAVSpec.getRelationEdges().isEmpty());
        }

        assertNotNull(assetVertices.get(2).getAssetCPE());
        assertNull(assetVertices.get(2).getParent());

        List<Map<String, Object>> m1 = cgm.findAll();
        assertEquals(2, m1.size());

        List<Map<String, Object>> m2 = cgm.findByCve("CVE-2018-20834");
        assertEquals(2, m2.size());
    }

    @Test
    void testAllNegate() throws IOException {
        Path path = Paths.get("src", "test", "resources", "assets", "cve", "entries", "nvdentry-all-negate.json");
        DefCveItem cveItem = OBJECT_MAPPER.readValue(path.toFile(), DefCveItem.class);

        Graph graph = TinkerGraph.open();
        FramedGraph fg = new DelegatingFramedGraph<>(graph, true, false);
        ScopedGraph sg = new ScopedGraph(fg);
        CpeGraphMatcher cgm = new CpeGraphMatcher(sg);

        CveVertex v1 = sg.createV(cveItem, CveVertex.class);
        Object vid1 = sg.findVByUid("CVE-0000-0001", CveVertex.class).orElseThrow().getId();

        assertEquals(v1.getId(), vid1);

        assetList.forEach(a -> sg.createV(a, AssetVertex.class));

        int result = sg.V(AssetVertex.class).toList(AssetVertex.class).size();
        assertEquals(5, result);

        List<Map<String, Object>> r1 = cgm.findByCve("CVE-0000-0001");
        assertEquals(4, r1.size());
    }

    @Test
    void testAllNegateButOne() throws IOException {
        Path path = Paths.get("src", "test", "resources", "assets", "cve", "entries", "nvdentry-all-negate-but-one.json");
        DefCveItem cveItem = OBJECT_MAPPER.readValue(path.toFile(), DefCveItem.class);

        Graph graph = TinkerGraph.open();
        FramedGraph fg = new DelegatingFramedGraph<>(graph, true, false);
        ScopedGraph sg = new ScopedGraph(fg);
        CpeGraphMatcher cgm = new CpeGraphMatcher(sg);

        sg.createV(cveItem, CveVertex.class);
        assetList.forEach(a -> sg.createV(a, AssetVertex.class));

        List<Map<String, Object>> r1 = cgm.findByCve("CVE-0000-0014");
        assertEquals(1, r1.size());

        Vertex v = ((Map<String, Vertex>) r1.get(0).get("match")).get("x_RootAsset");
        AssetVertex c = fg.traverse(t -> t.V().hasId(P.eq(v.id()))).next(AssetVertex.class);

        assertEquals("131b6b1c-3ba9-11eb-adc1-0242ac120002", c.getUid());
    }
}
