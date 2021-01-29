package cz.muni.csirt.nvd.cpe.transform.wfn;

import gov.nist.secauto.cpe.common.LogicalValue;
import gov.nist.secauto.cpe.common.WellFormedName;
import gov.nist.secauto.cpe.naming.util.CPEFormattedStringName;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class AVSpecUtil {

    public static List<TargetAVSpec> getTargetAVSpecs(WellFormedName wfn) {
        return extractFromWfn(wfn)
                .stream()
                .map(TargetAVSpec::new)
                .collect(Collectors.toList());
    }

    public static List<SourceAVSpec> getSourceAVSpecs(String formattedString) {
        return getSourceAVSpecs(formattedString, new StringRange());
    }

    public static List<SourceAVSpec> getSourceAVSpecs(String formattedString, StringRange versionStringRange) {
        if (versionStringRange == null) {
            throw new NullPointerException("versionStringRange cannot be null.");
        }

        return extractFromWfn(unbindToWfn(formattedString))
                .stream()
                .map(p -> handleAVPairWithVersion(p, versionStringRange))
                .collect(Collectors.toList());
    }

    public static WellFormedName unbindToWfn(String formattedString) {
        try {
            CPEFormattedStringName fsn = new CPEFormattedStringName(formattedString);
            return fsn.getWellFormedName();
        } catch (ParseException e) {
            throw new IllegalArgumentException("The argument is not a valid CPE v2.3 FSN.", e);
        }
    }

    public static List<AVPair> extractFromWfn(WellFormedName wfn) {
        return Arrays
                .stream(WellFormedName.Attribute.values())
                .map(a -> handleAttribute(a, wfn.get(a)))
                .collect(Collectors.toList());
    }

    private static SourceAVSpec handleAVPairWithVersion(AVPair avPair, StringRange versionStringRange) {
        if (avPair.getAttribute() == WellFormedName.Attribute.VERSION) {
            return new SourceAVSpec(avPair, versionStringRange);
        }

        return new SourceAVSpec(avPair);
    }

    private static AVPair handleAttribute(WellFormedName.Attribute attribute, Object value) {
        if (value instanceof LogicalValue) {
            LogicalValue v = (LogicalValue) value;
            AVPairType type = AVPairType.valueOf(v.name());
            return new AVPair(attribute, type, type.name());
        }

        return new AVPair(attribute, AVPairType.VALUE, (String) value);
    }
}
