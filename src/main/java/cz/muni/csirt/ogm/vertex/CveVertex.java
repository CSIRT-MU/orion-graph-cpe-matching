package cz.muni.csirt.ogm.vertex;

import cz.muni.csirt.nvd.cpe.transform.statement.StatementCNF;
import cz.muni.csirt.nvd.cpe.transform.statement.StatementUtil;
import cz.muni.csirt.ogm.ScopedGraph;
import cz.muni.csirt.ogm.vertex.base.ScopedVertex;
import cz.muni.csirt.ogm.vertex.statement.StatementVertex;
import gov.nist.nvd.feed.cve.*;

import java.util.List;
import java.util.Map;

public class CveVertex extends ScopedVertex<DefCveItem> {

    public CVEJSON40Min11Beta getCve() {
        return getJSONProperty("cve", CVEJSON40Min11Beta.class);
    }

    public void setCve(CVEJSON40Min11Beta cve) {
        setJSONProperty("cve", cve);
    }

    public DefConfigurations getConfigurations() {
        return getJSONProperty("configurations", DefConfigurations.class);
    }

    public void setConfigurations(DefConfigurations configurations) {
        setJSONProperty("configurations", configurations);
    }

    public DefImpact getImpact() {
        return getJSONProperty("impact", DefImpact.class);
    }

    public void setImpact(DefImpact impact) {
        setJSONProperty("impact", impact);
    }

    public String getPublishedDate() {
        return getProperty("publishedDate");
    }

    public void setPublishedDate(String publishedDate) {
        setProperty("publishedDate", publishedDate);
    }

    public String getLastModifiedDate() {
        return getProperty("lastModifiedDate");
    }

    public void setLastModifiedDate(String lastModifiedDate) {
        setProperty("lastModifiedDate", lastModifiedDate);
    }

    public Map<String, Object> getAdditionalProperties() {
        return getJSONProperty("additionalProperties", MAP_TYPE);
    }

    public void setAdditionalProperties(Map<String, Object> additionalProperties) {
        setJSONProperty("additionalProperties", additionalProperties);
    }

    public List<? extends StatementVertex> getStatements() {
        return traverse(v -> v.out("hasStatement")).toList(StatementVertex.class);
    }

    public void addStatement(StatementVertex vertex) {
        linkOut(vertex, "hasStatement");
    }

    @Override
    public String extractUid(DefCveItem dto) {
        return dto.getCve().getCVEDataMeta().getId();
    }

    @Override
    public void initialize(DefCveItem cveItem, ScopedGraph sg) {
        setCve(cveItem.getCve());
        setConfigurations(cveItem.getConfigurations());
        setImpact(cveItem.getImpact());
        setPublishedDate(cveItem.getPublishedDate());
        setLastModifiedDate(cveItem.getLastModifiedDate());
        setAdditionalProperties(cveItem.getAdditionalProperties());

        for (DefNode rootNode : cveItem.getConfigurations().getNodes()) {
            StatementCNF statement = StatementUtil.fromNVDApplicabilityStatement(rootNode);
            StatementVertex v = sg.createUnscopedV(statement, StatementVertex.class);
            addStatement(v);
        }

    }
}
