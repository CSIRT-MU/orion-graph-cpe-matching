package cz.muni.csirt.ogm.vertex.statement;

import cz.muni.csirt.nvd.cpe.transform.statement.element.FactRef;
import cz.muni.csirt.nvd.cpe.transform.wfn.AVSpecUtil;
import cz.muni.csirt.nvd.cpe.transform.wfn.SourceAVSpec;
import cz.muni.csirt.nvd.cpe.transform.wfn.StringRange;
import cz.muni.csirt.nvd.cpe.transform.wfn.StringRangeUtil;
import cz.muni.csirt.ogm.ScopedGraph;
import cz.muni.csirt.ogm.vertex.base.UnscopedVertex;
import cz.muni.csirt.ogm.vertex.wfn.SourceAVSpecVertex;
import gov.nist.nvd.feed.cve.DefCpeMatch;
import org.apache.commons.lang3.BooleanUtils;

import java.util.List;

public class FactRefVertex extends UnscopedVertex<FactRef> {

    public String getVulnerable() {
        return getProperty("vulnerable");
    }

    public void setVulnerable(boolean vulnerable) {
        setProperty("vulnerable", vulnerable);
    }

    public String getCpe23Uri() {
        return getProperty("cpe23Uri");
    }

    public void setCpe23Uri(String cpe23Uri) {
        setProperty("cpe23Uri", cpe23Uri);
    }

    public StringRange getVersionStringRange() {
        return getJSONProperty("versionStringRange", StringRange.class);
    }

    public void setVersionStringRange(StringRange versionStringRange) {
        setJSONProperty("versionStringRange", versionStringRange);
    }

    public DefCpeMatch getDefCpeMatch() {
        return getJSONProperty("defCpeMatch", DefCpeMatch.class);
    }

    public void setDefCpeMatch(DefCpeMatch defCpeMatch) {
        setJSONProperty("defCpeMatch", defCpeMatch);
    }

    public List<? extends SourceAVSpecVertex> getSourceAVSpecs() {
        return traverse(v -> v.out("hasSourceAVSpec")).toList(SourceAVSpecVertex.class);
    }

    public void addSourceAVSpec(SourceAVSpecVertex vertex) {
        linkOut(vertex, "hasSourceAVSpec");
    }

    @Override
    public void initialize(FactRef dto, ScopedGraph sg) {
        DefCpeMatch defCpeMatch = dto.getCpeMatch();
        setDefCpeMatch(defCpeMatch);

        setVulnerable(BooleanUtils.isTrue(defCpeMatch.getVulnerable()));
        setCpe23Uri(defCpeMatch.getCpe23Uri());

        StringRange versionStringRange = StringRangeUtil.from(
                defCpeMatch.getVersionStartIncluding(),
                defCpeMatch.getVersionStartExcluding(),
                defCpeMatch.getVersionEndIncluding(),
                defCpeMatch.getVersionEndExcluding()
        );

        setVersionStringRange(versionStringRange);

        List<SourceAVSpec> specs = AVSpecUtil.getSourceAVSpecs(defCpeMatch.getCpe23Uri(), versionStringRange);
        for (SourceAVSpec spec : specs) {
            // The SourceAVSpecVertex is scoped and it will be present only once in the graph for each uid
            addSourceAVSpec(sg.getOrCreateV(spec, SourceAVSpecVertex.class));
        }
    }
}
