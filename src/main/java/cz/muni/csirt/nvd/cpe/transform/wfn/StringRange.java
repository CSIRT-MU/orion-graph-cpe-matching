package cz.muni.csirt.nvd.cpe.transform.wfn;

import java.util.StringJoiner;

public class StringRange {

    private boolean startInclusive = false;
    private boolean endInclusive = false;

    private String start = null;
    private String end = null;

    public boolean isStartInclusive() {
        return startInclusive;
    }

    public void setStartInclusive(boolean startInclusive) {
        this.startInclusive = startInclusive;
    }

    public boolean isEndInclusive() {
        return endInclusive;
    }

    public void setEndInclusive(boolean endInclusive) {
        this.endInclusive = endInclusive;
    }

    public String getStart() {
        return start;
    }

    public void setStart(String start) {
        this.start = start;
    }

    public String getEnd() {
        return end;
    }

    public void setEnd(String end) {
        this.end = end;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", StringRange.class.getSimpleName() + "[", "]")
                .add("startInclusive=" + startInclusive)
                .add("endInclusive=" + endInclusive)
                .add("start='" + start + "'")
                .add("end='" + end + "'")
                .toString();
    }
}
