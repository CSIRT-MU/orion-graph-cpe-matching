package cz.muni.csirt.nvd.cpe;

import com.fasterxml.jackson.databind.ObjectMapper;
import cz.muni.csirt.nvd.cpe.transform.wfn.*;
import gov.nist.nvd.feed.cve.DefCveItem;
import gov.nist.nvd.feed.cve.NvdCveFeedJson11Beta;
import gov.nist.secauto.cpe.common.LogicalValue;
import gov.nist.secauto.cpe.common.WellFormedName;
import gov.nist.secauto.cpe.matching.CPENameMatcher;
import gov.nist.secauto.cpe.matching.Relation;
import gov.nist.secauto.cpe.naming.util.CPEFormattedStringName;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.*;

class CPECommonTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void testPartComparison() {
        assertEquals(Relation.SUPERSET, ReferenceImplAccess.compare(LogicalValue.ANY, "foo"));
        assertEquals(Relation.SUBSET, ReferenceImplAccess.compare("foo", LogicalValue.ANY));
        assertEquals(Relation.SUBSET, ReferenceImplAccess.compare(LogicalValue.NA, LogicalValue.ANY));
        assertEquals(Relation.UNDEFINED, ReferenceImplAccess.compare(LogicalValue.NA, "windows??"));
    }

    @Test
    void testAVSpecUtils() throws ParseException {
        String fs = "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:itanium:*";
        List<SourceAVSpec> avSpecs1 = AVSpecUtil.getSourceAVSpecs(fs);
        assertEquals(11, avSpecs1.size());

        WellFormedName wfn = AVSpecUtil.unbindToWfn(fs);
        List<TargetAVSpec> avSpecs2 = AVSpecUtil.getTargetAVSpecs(wfn);
        assertEquals(11, avSpecs2.size());

        assertThrows(NullPointerException.class, () -> AVSpecUtil.getSourceAVSpecs(fs, null));
    }

    @Test
    void testStringRanges() {
        StringRange r1 = StringRangeUtil.from(null, null, null, null);

        assertEquals("StringRange[startInclusive=false, endInclusive=false, start='null', end='null']", r1.toString());
        assertNull(r1.getStart());
        assertNull(r1.getEnd());
        assertFalse(r1.isStartInclusive());
        assertFalse(r1.isEndInclusive());

        StringRange r2 = StringRangeUtil.from("A", "B", "E", "F");

        assertEquals("StringRange[startInclusive=true, endInclusive=true, start='A', end='E']", r2.toString());
        assertEquals("A", r2.getStart());
        assertTrue(r2.isStartInclusive());
        assertEquals("E", r2.getEnd());
        assertTrue(r2.isEndInclusive());

        StringRange r3 = StringRangeUtil.from(null, "B", null, "F");

        assertEquals("StringRange[startInclusive=false, endInclusive=false, start='B', end='F']", r3.toString());
        assertEquals("B", r3.getStart());
        assertFalse(r3.isStartInclusive());
        assertEquals("F", r3.getEnd());
        assertFalse(r3.isEndInclusive());

        StringRange r4 = StringRangeUtil.from("A", null, "E", null);

        assertEquals("StringRange[startInclusive=true, endInclusive=true, start='A', end='E']", r4.toString());
        assertEquals("A", r4.getStart());
        assertTrue(r4.isStartInclusive());
        assertEquals("E", r4.getEnd());
        assertTrue(r4.isEndInclusive());

        StringRange r5 = StringRangeUtil.from(null, null, null, "F");

        assertEquals("StringRange[startInclusive=false, endInclusive=false, start='null', end='F']", r5.toString());
        assertNull(r5.getStart());
        assertFalse(r5.isStartInclusive());
        assertEquals("F", r5.getEnd());
        assertFalse(r5.isEndInclusive());

        assertFalse(StringRangeUtil.inRange(null, r1));
        assertTrue(StringRangeUtil.inRange("C", r1));
        assertTrue(StringRangeUtil.inRange("C", r2));
        assertTrue(StringRangeUtil.inRange("C", r3));
        assertTrue(StringRangeUtil.inRange("C", r4));
        assertTrue(StringRangeUtil.inRange("C", r5));

        assertTrue(StringRangeUtil.inRange("B", r1));
        assertTrue(StringRangeUtil.inRange("B", r2));
        assertFalse(StringRangeUtil.inRange("B", r3));
        assertTrue(StringRangeUtil.inRange("B", r4));
        assertTrue(StringRangeUtil.inRange("B", r5));

        assertTrue(StringRangeUtil.inRange("E", r1));
        assertTrue(StringRangeUtil.inRange("E", r2));
        assertTrue(StringRangeUtil.inRange("E", r3));
        assertFalse(StringRangeUtil.inRange("F", r3));
        assertTrue(StringRangeUtil.inRange("E", r4));
        assertTrue(StringRangeUtil.inRange("E", r5));
        assertFalse(StringRangeUtil.inRange("F", r5));
    }

    @Test
    void testCPEMAtch() throws ParseException {
        WellFormedName target = new WellFormedName();
        target.set(WellFormedName.Attribute.VENDOR, "apache");

        WellFormedName source = new CPEFormattedStringName("cpe:2.3:a:apache:commons-text:1.6:*:*:*:*:*:*:*").getWellFormedName();

        assertTrue(CPENameMatcher.isSubset(source, target));
    }

    @Test
    void testMapping1() throws IOException {
        Path path = Paths.get("src", "test", "resources", "assets", "cve", "entries", "nvdentry1.json");
        DefCveItem cve = OBJECT_MAPPER.readValue(path.toFile(), DefCveItem.class);

        assertEquals("2020-09-29T01:49Z", cve.getLastModifiedDate());
        assertEquals(7, cve.getConfigurations().getNodes().size());
    }

    @Test
    void testMapping2() throws IOException {
        Path path = Paths.get("src", "test", "resources", "assets", "cve", "entries", "nvdentry2.json");
        DefCveItem cve = OBJECT_MAPPER.readValue(path.toFile(), DefCveItem.class);

        assertEquals("2019-05-17T20:08Z", cve.getLastModifiedDate());
        assertEquals(1, cve.getConfigurations().getNodes().size());
    }

    @Test
    void testMapping3() throws IOException {
        Path path = Paths.get("src", "test", "resources", "assets", "cve", "entries", "nvdentry3.json");
        DefCveItem cve = OBJECT_MAPPER.readValue(path.toFile(), DefCveItem.class);

        assertEquals("2019-09-04T20:15Z", cve.getLastModifiedDate());
        assertEquals(1, cve.getConfigurations().getNodes().size());
        assertEquals("4.4.2", cve.getConfigurations()
                .getNodes()
                .get(0)
                .getCpeMatch()
                .get(1)
                .getVersionEndExcluding());
    }

    @Test
    void testParseCpeName() throws IOException, ParseException {
        Path path = Paths.get("src", "test", "resources", "assets", "cve", "entries", "nvdentry2.json");
        DefCveItem cve = OBJECT_MAPPER.readValue(path.toFile(), DefCveItem.class);

        String cpe23Uri = cve.getConfigurations()
                .getNodes()
                .get(0)
                .getCpeMatch()
                .get(8)
                .getCpe23Uri();

        String expected = "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:itanium:*";
        assertEquals(expected, cpe23Uri);

        WellFormedName wfn = (new CPEFormattedStringName(cpe23Uri)).getWellFormedName();

        assertEquals("itanium", wfn.get(WellFormedName.Attribute.TARGET_HW));
    }

    @Test
    void testReadFeedArchive() throws IOException {
        Path path = Paths.get("src", "test", "resources", "assets", "cve", "feeds", "nvdcve-1.1-2011.json.gz");

        InputStream gzipStream = new GZIPInputStream(new FileInputStream(path.toFile()));
        BufferedReader buffered = new BufferedReader(new InputStreamReader(gzipStream, StandardCharsets.UTF_8));

        NvdCveFeedJson11Beta feed = OBJECT_MAPPER.readValue(buffered, NvdCveFeedJson11Beta.class);

        buffered.close();

        assertEquals(4813, feed.getCVEItems().size());
    }

    @Test
    void testWfnPartExtraction() {
        String cpeString = "cpe:2.3:a:apache:commons-text:1.6:*:*:*:-:*:*:*";
        Map<WellFormedName.Attribute, AVPair> parts = AVSpecUtil
                .extractFromWfn(AVSpecUtil.unbindToWfn(cpeString))
                .stream()
                .collect(Collectors.toMap(AVPair::getAttribute, p -> p));

        AVPair swEdition = parts.get(WellFormedName.Attribute.SW_EDITION);
        Object swEditionValue = swEdition.getValueForComparison();

        assertEquals(AVPairType.NA, swEdition.getType());
        assertTrue(swEditionValue instanceof LogicalValue);
        assertEquals(Relation.EQUAL, ReferenceImplAccess.compare(swEditionValue, LogicalValue.NA));
        assertEquals(Relation.DISJOINT, ReferenceImplAccess.compare(swEditionValue, "string"));
    }

    @Test
    void testValueEscaping() throws ParseException {
        WellFormedName wfn = new CPEFormattedStringName("cpe:2.3:a:apache:commons-text:1.6.7_SNAPSHOT:*:*:*:*:*:*:*").getWellFormedName();

        assertEquals("1\\.6\\.7_SNAPSHOT", wfn.get(WellFormedName.Attribute.VERSION));
    }
}