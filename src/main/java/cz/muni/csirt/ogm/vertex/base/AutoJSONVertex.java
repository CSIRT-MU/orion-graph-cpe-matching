package cz.muni.csirt.ogm.vertex.base;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.MapType;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.syncleus.ferma.AbstractVertexFrame;

import java.util.HashMap;

public abstract class AutoJSONVertex extends AbstractVertexFrame {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    protected static final TypeFactory TYPE_FACTORY = TypeFactory.defaultInstance();
    protected static final MapType MAP_TYPE = TYPE_FACTORY.constructMapType(HashMap .class, String.class, String.class);

    public static final String JSON_PREFIX = "JSON_";

    public <S> S getJSONProperty(final String name, Class<S> aClass) {
        return getJSONProperty(name, TYPE_FACTORY.constructType(aClass));
    }

    public <S> S getJSONProperty(final String name, JavaType javaType) {
        return fromJson(super.getProperty(JSON_PREFIX + name), javaType);
    }

    public void setJSONProperty(final String name, final Object value) {
        super.setProperty(JSON_PREFIX + name, toJson(value));
    }

    private static String toJson(Object o) {
        try {
            return OBJECT_MAPPER.writeValueAsString(o);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Cannot serialize object into JSON.", e);
        }
    }

    private static <J> J fromJson(String s, JavaType javaType) {
        try {
            return OBJECT_MAPPER.readValue(s, javaType);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Cannot de-serialize object from JSON.", e);
        }
    }
}
