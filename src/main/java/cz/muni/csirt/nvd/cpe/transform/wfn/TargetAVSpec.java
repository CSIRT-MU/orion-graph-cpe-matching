package cz.muni.csirt.nvd.cpe.transform.wfn;

import java.util.StringJoiner;

public class TargetAVSpec {

    private final AVPair avPair;

    public TargetAVSpec(AVPair avPair) {
        this.avPair = avPair;
    }

    public AVPair getAVPair() {
        return avPair;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", TargetAVSpec.class.getSimpleName() + "[", "]")
                .add("avPair=" + avPair)
                .toString();
    }
}
