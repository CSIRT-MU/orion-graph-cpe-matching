package cz.muni.csirt.asset;

import java.util.StringJoiner;
import java.util.UUID;

public class SimpleAsset {

    private UUID uuid;
    private String name;
    private String cpe23fs;
    private UUID parentUuid;

    public SimpleAsset() {
    }

    public SimpleAsset(UUID uuid, String name, String cpe23fs, UUID parentUuid) {
        this.uuid = uuid;
        this.name = name;
        this.cpe23fs = cpe23fs;
        this.parentUuid = parentUuid;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCpe23fs() {
        return cpe23fs;
    }

    public void setCpe23fs(String cpe23fs) {
        this.cpe23fs = cpe23fs;
    }

    public UUID getParentUuid() {
        return parentUuid;
    }

    public void setParentUuid(UUID parentUuid) {
        this.parentUuid = parentUuid;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", SimpleAsset.class.getSimpleName() + "[", "]")
                .add("uuid=" + uuid)
                .add("name='" + name + "'")
                .add("cpe23fs='" + cpe23fs + "'")
                .add("parentUuid=" + parentUuid)
                .toString();
    }
}
