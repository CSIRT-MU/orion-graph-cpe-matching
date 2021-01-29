package cz.muni.csirt.matching;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.syncleus.ferma.DelegatingFramedGraph;
import com.syncleus.ferma.FramedGraph;
import cz.muni.csirt.asset.SimpleAsset;
import cz.muni.csirt.ogm.ScopedGraph;
import cz.muni.csirt.ogm.vertex.CveVertex;
import cz.muni.csirt.ogm.vertex.asset.AssetVertex;
import gov.nist.nvd.feed.cve.DefCveItem;
import gov.nist.nvd.feed.cve.NvdCveFeedJson11Beta;
import org.apache.tinkerpop.gremlin.structure.Vertex;
import org.janusgraph.core.JanusGraph;
import org.janusgraph.core.JanusGraphFactory;
import org.janusgraph.core.PropertyKey;
import org.janusgraph.core.schema.JanusGraphManagement;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CVEJanusGraphMatchingTest {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
	private List<DefCveItem> cveList;
	private List<SimpleAsset> assetList;

	@BeforeEach
	void setUp() throws IOException {
		// All assets
		Path path = Paths.get("src", "test", "resources", "assets", "cve", "assets.json");
		CollectionType type = OBJECT_MAPPER.getTypeFactory().constructCollectionType(ArrayList.class, SimpleAsset.class);
		assetList = OBJECT_MAPPER.readValue(Files.readString(path), type);

		// Multiple feed vulnerabilities
		Path p1 = Paths.get("src", "test", "resources", "assets", "cve", "feeds", "nvdcve-1.1-2011.json.gz");
		InputStream gzipStream = new GZIPInputStream(new FileInputStream(p1.toFile()));
		BufferedReader buffered = new BufferedReader(new InputStreamReader(gzipStream, StandardCharsets.UTF_8));
		NvdCveFeedJson11Beta nvdFeed = OBJECT_MAPPER.readValue(buffered, NvdCveFeedJson11Beta.class);
		buffered.close();

		cveList = nvdFeed.getCVEItems().subList(32, 43);

		// Additional vulnerabilities
		Path p2 = Paths.get("src", "test", "resources", "assets", "cve", "entries", "nvdentry3.json");
		Path p3 = Paths.get("src", "test", "resources", "assets", "cve", "entries", "nvdentry-all-negate.json");
		Path p4 = Paths.get("src", "test", "resources", "assets", "cve", "entries", "nvdentry-all-negate-but-one.json");

		cveList.add(OBJECT_MAPPER.readValue(p2.toFile(), DefCveItem.class));
		cveList.add(OBJECT_MAPPER.readValue(p3.toFile(), DefCveItem.class));
		cveList.add(OBJECT_MAPPER.readValue(p4.toFile(), DefCveItem.class));
	}

	@Test
	void testAllJanusGraph() {
		JanusGraph graph = JanusGraphFactory.build().set("storage.backend", "inmemory").open();
		createIndexes(graph);

		FramedGraph fg = new DelegatingFramedGraph<>(graph, true, false);
		ScopedGraph sg = new ScopedGraph(fg);
		CpeGraphMatcher cgm = new CpeGraphMatcher(sg);

		cveList.forEach(e -> sg.createV(e, CveVertex.class));
		assetList.forEach(a -> sg.createV(a, AssetVertex.class));

		assertEquals(14, sg.V(CveVertex.class).getRawTraversal().count().next());

		List<Map<String, Object>> r1 = cgm.findByCve("CVE-2018-20834");
		assertEquals(2, r1.size());

		List<Map<String, Object>> r2 = cgm.findByCve("CVE-0000-0001");
		assertEquals(4, r2.size());

		List<Map<String, Object>> r3 = cgm.findByCve("CVE-0000-0014");
		assertEquals(1, r3.size());

		List<Map<String, Object>> rAll = cgm.findAll();
		assertEquals(7, rAll.size());

		List<Map<String, Object>> rAsset = cgm.findByAsset("a84fa9de-de42-443f-87b2-0d892ecdb8f5");
		assertEquals(2, rAsset.size());
	}

	private void createIndexes(JanusGraph graph) {
		JanusGraphManagement management = graph.openManagement();
		PropertyKey k1 = management.makePropertyKey("ferma_type").dataType(String.class).make();
		PropertyKey k2 = management.makePropertyKey("uid").dataType(String.class).make();
		PropertyKey k3 = management.makePropertyKey("attribute").dataType(String.class).make();
		management.buildIndex("byFermaIndex", Vertex.class)
				.addKey(k1)
				.buildCompositeIndex();
		management.buildIndex("byFermaAndUidIndex", Vertex.class)
				.addKey(k1)
				.addKey(k2)
				.buildCompositeIndex();
		management.buildIndex("byFermaAndAttributeIndex", Vertex.class)
				.addKey(k1)
				.addKey(k3)
				.buildCompositeIndex();
		management.commit();
	}
}
