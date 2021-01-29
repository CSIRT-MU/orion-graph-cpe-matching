package cz.muni.csirt.ogm.vertex.asset;

import cz.muni.csirt.asset.SimpleAsset;
import cz.muni.csirt.nvd.cpe.transform.wfn.AVSpecUtil;
import cz.muni.csirt.ogm.ScopedGraph;
import cz.muni.csirt.ogm.vertex.base.ScopedVertex;
import gov.nist.secauto.cpe.common.WellFormedName;

import java.util.Optional;
import java.util.UUID;

public class AssetVertex extends ScopedVertex<SimpleAsset> {

    public String getName() {
        return getProperty("name");
    }

    public void setName(String name) {
        setProperty("name", name);
    }

    public AssetVertex getParent() {
        return traverse(t -> t.out("hasParent")).nextOrDefault(AssetVertex.class, null);
    }

    public void setParent(AssetVertex vertex) {
        setLinkOut(vertex, "hasParent");
    }

    public AssetCPEVertex getAssetCPE() {
        return traverse(t -> t.in("classifies")).next(AssetCPEVertex.class);
    }

    public void setAssetCPE(AssetCPEVertex vertex) {
        setLinkIn(vertex, "classifies");
    }

    @Override
    public String extractUid(SimpleAsset dto) {
        return dto.getUuid().toString();
    }

    @Override
    public void initialize(SimpleAsset dto, ScopedGraph sg) {
        setName(dto.getName());
        UUID parentUuid = dto.getParentUuid();

        if (parentUuid != null) {
            Optional<AssetVertex> parentVertex = sg.findVByUid(parentUuid.toString(), AssetVertex.class);
            parentVertex.ifPresent(this::setParent); // the parent will not be set if not found in graph
        }

        WellFormedName wfn = AVSpecUtil.unbindToWfn(dto.getCpe23fs());
        setAssetCPE(sg.createUnscopedV(wfn, AssetCPEVertex.class));
    }
}
