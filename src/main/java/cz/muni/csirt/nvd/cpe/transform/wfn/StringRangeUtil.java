package cz.muni.csirt.nvd.cpe.transform.wfn;

import cz.muni.csirt.nvd.cpe.ReferenceImplAccess;

public class StringRangeUtil {

    public static StringRange from(String startIncluding, String startExcluding, String endIncluding, String endExcluding) {
        StringRange r = buildStart(startIncluding, startExcluding);
        StringRange s = buildEnd(endIncluding, endExcluding);

        r.setEnd(s.getEnd());
        r.setEndInclusive(s.isEndInclusive());

        return r;
    }

    public static boolean inRange(String string, StringRange filter) {
        if (string == null) {
            return false;
        }

        String start = filter.getStart();
        String end = filter.getEnd();

        boolean startMatch = true;
        if (start != null) {
            int a = start.compareTo(string);
            if (a == 0) {
                startMatch = filter.isStartInclusive();
            } else {
                startMatch = a < 0;
            }
        }

        boolean endMatch = true;
        if (end != null) {
            int a = end.compareTo(string);
            if (a == 0) {
                endMatch = filter.isEndInclusive();
            } else {
                endMatch = a > 0;
            }
        }

        return startMatch && endMatch;
    }

    private static StringRange buildStart(String startIncluding, String startExcluding) {
        StringRange r = new StringRange();

        if (startIncluding != null) {
            r.setStart(quote(startIncluding));
            r.setStartInclusive(true);
            return r;
        }

        if (startExcluding != null) {
            r.setStart(quote(startExcluding));
            r.setStartInclusive(false);
            return r;
        }

        return r;
    }

    private static StringRange buildEnd(String endIncluding, String endExcluding) {
        StringRange r = new StringRange();

        if (endIncluding != null) {
            r.setEnd(quote(endIncluding));
            r.setEndInclusive(true);
            return r;
        }

        if (endExcluding != null) {
            r.setEnd(quote(endExcluding));
            r.setEndInclusive(false);
            return r;
        }

        return r;
    }

    private static String quote(String version) {
        return ReferenceImplAccess.addQuoting(version);
    }
}
