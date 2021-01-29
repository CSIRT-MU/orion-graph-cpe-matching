package cz.muni.csirt.ogm.vertex.base;

public abstract class ScopedVertex<T> extends UnscopedVertex<T> {

    public static final String UID_ATTR = "uid";

    public String getUid() {
        return getProperty(UID_ATTR);
    }

    public void setUid(String uid) {
        setProperty(UID_ATTR, uid);
    }

    public abstract String extractUid(T dto);
}
