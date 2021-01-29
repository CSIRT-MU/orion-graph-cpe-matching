package cz.muni.csirt.nvd.cpe.transform.wfn;

import java.util.StringJoiner;

public class SourceAVSpec {

    private final AVPair avPair;
    private final StringRange stringRange;

    public SourceAVSpec(AVPair avPair) {
        this(avPair, null);
    }

    public SourceAVSpec(AVPair avPair, StringRange stringRange) {
        this.avPair = avPair;
        this.stringRange = stringRange;
    }

    public AVPair getAVPair() {
        return avPair;
    }

    public StringRange getStringRange() {
        return stringRange;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", SourceAVSpec.class.getSimpleName() + "[", "]")
                .add("avPair=" + avPair)
                .add("stringRange=" + stringRange)
                .toString();
    }
}
