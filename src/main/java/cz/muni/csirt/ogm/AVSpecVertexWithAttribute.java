package cz.muni.csirt.ogm;

import gov.nist.secauto.cpe.common.WellFormedName;

public interface AVSpecVertexWithAttribute {

	WellFormedName.Attribute getAttribute();

	void setAttribute(WellFormedName.Attribute attribute);
}
