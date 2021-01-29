package cz.muni.csirt.ogm.edge;

import com.syncleus.ferma.AbstractEdgeFrame;
import gov.nist.secauto.cpe.matching.Relation;

public class RelationEdge extends AbstractEdgeFrame {

    public Relation getRelation() {
        return Relation.valueOf(getProperty("relation"));
    }

    public void setRelation(Relation relation) {
        setProperty("relation", relation.toString());
    }

}
