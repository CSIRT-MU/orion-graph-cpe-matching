package cz.muni.csirt.nvd.cpe;

import gov.nist.secauto.cpe.matching.CPENameMatcher;
import gov.nist.secauto.cpe.matching.Relation;
import gov.nist.secauto.cpe.naming.CPENameUnbinder;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class ReferenceImplAccess {

    public static Relation compare(Object source, Object target) {
        try {
            return compareReflective(source, target);
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    public static String addQuoting(String str) {
        try {
            return addQuotingReflective(str);
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    private static Relation compareReflective(Object source, Object target) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Method method = CPENameMatcher.class.getDeclaredMethod("compare", Object.class, Object.class);
        method.setAccessible(true);
        return (Relation) method.invoke(CPENameMatcher.class, source, target);
    }

    private static String addQuotingReflective(String str) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Method method = CPENameUnbinder.class.getDeclaredMethod("addQuoting", String.class);
        method.setAccessible(true);
        return (String) method.invoke(CPENameUnbinder.class, str);
    }
}
