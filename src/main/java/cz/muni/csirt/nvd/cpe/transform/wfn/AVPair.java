package cz.muni.csirt.nvd.cpe.transform.wfn;

import com.fasterxml.jackson.annotation.JsonIgnore;
import gov.nist.secauto.cpe.common.LogicalValue;
import gov.nist.secauto.cpe.common.WellFormedName;

import java.util.StringJoiner;

public class AVPair {

    private WellFormedName.Attribute attribute;
    private AVPairType type;
    private String value;

    public AVPair() {
    }

    public AVPair(WellFormedName.Attribute attribute, AVPairType type, String value) {
        this.attribute = attribute;
        this.type = type;
        this.value = value;
    }

    public WellFormedName.Attribute getAttribute() {
        return attribute;
    }

    public void setAttribute(WellFormedName.Attribute attribute) {
        this.attribute = attribute;
    }

    public AVPairType getType() {
        return type;
    }

    public void setType(AVPairType type) {
        this.type = type;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @JsonIgnore
    public Object getValueForComparison() {
        if (type == AVPairType.VALUE) {
            return value;
        }

        return LogicalValue.valueOf(type.name());
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", AVPair.class.getSimpleName() + "[", "]")
                .add("attribute=" + attribute)
                .add("type=" + type)
                .add("value='" + value + "'")
                .toString();
    }
}
