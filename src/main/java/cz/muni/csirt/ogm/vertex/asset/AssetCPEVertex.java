package cz.muni.csirt.ogm.vertex.asset;

import cz.muni.csirt.nvd.cpe.transform.wfn.AVSpecUtil;
import cz.muni.csirt.nvd.cpe.transform.wfn.TargetAVSpec;
import cz.muni.csirt.ogm.ScopedGraph;
import cz.muni.csirt.ogm.vertex.base.UnscopedVertex;
import cz.muni.csirt.ogm.vertex.wfn.TargetAVSpecVertex;
import gov.nist.secauto.cpe.common.WellFormedName;
import gov.nist.secauto.cpe.naming.CPENameBinder;

import java.util.List;

public class AssetCPEVertex extends UnscopedVertex<WellFormedName> {

    public String getCpe23fs() {
        return getProperty("cpe23fs");
    }

    public void setCpe23fs(String cpe23fs) {
        setProperty("cpe23fs", cpe23fs);
    }

    public List<? extends TargetAVSpecVertex> getTargetAVSpecs() {
        return traverse(v -> v.out("hasTargetAVSpec")).toList(TargetAVSpecVertex.class);
    }

    public void addTargetAVSpec(TargetAVSpecVertex vertex) {
        linkOut(vertex, "hasTargetAVSpec");
    }

    @Override
    public void initialize(WellFormedName dto, ScopedGraph sg) {
        setCpe23fs(CPENameBinder.bindToFS(dto));

        List<TargetAVSpec> specs = AVSpecUtil.getTargetAVSpecs(dto);
        for (TargetAVSpec spec : specs) {
            // The TargetAVSpecVertex is scoped and it will be present only once in the graph for each uid
            addTargetAVSpec(sg.getOrCreateV(spec, TargetAVSpecVertex.class));
        }
    }
}
