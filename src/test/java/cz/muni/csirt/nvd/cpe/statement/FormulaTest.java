package cz.muni.csirt.nvd.cpe.statement;

import com.fasterxml.jackson.databind.ObjectMapper;
import cz.muni.csirt.nvd.cpe.transform.statement.StatementUtil;
import cz.muni.csirt.nvd.cpe.transform.statement.element.And;
import gov.nist.nvd.feed.cve.DefNode;
import org.junit.jupiter.api.Test;
import org.logicng.formulas.Formula;
import org.logicng.formulas.FormulaFactory;
import org.logicng.formulas.Literal;
import org.logicng.formulas.Variable;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class FormulaTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void testLogic() {
        FormulaFactory F = new FormulaFactory();
        Formula formula1 = F.or(F.not(F.variable("A")), F.constant(false));
        Formula formula2 = (F.not(F.variable("A")));
        assertEquals(formula1, formula2);
    }

    @Test
    void testCnfLogic() {
        final FormulaFactory f = new FormulaFactory();
        final Variable a = f.variable("A");
        final Variable b = f.variable("B");
        final Literal notC = f.literal("C", false);
        final Variable d = f.variable("D");

        Formula result = f.and(f.or(a, b, d), f.not(f.or(b, notC, d))).cnf();
        Formula expected = f.and(f.or(a, b, d), f.not(b), f.not(notC), f.not(d));

        assertEquals(expected, result);
    }

    @Test
    public void testStatementWithAnd() throws IOException {
        Path path = Paths.get("src", "test", "resources", "assets", "cve", "entries", "applicability-and.json");
        DefNode rootNode = OBJECT_MAPPER.readValue(path.toFile(), DefNode.class);

        List<And> cnfNodes = StatementUtil.fromNVDApplicabilityStatement(rootNode).getAndOperands();

        assertEquals(23, cnfNodes.size());
        assertEquals("cpe:2.3:o:juniper:junos:12.1x46:*:*:*:*:*:*:*", cnfNodes
                .get(0)
                .getOrOperands()
                .get(0)
                .getFactRef()
                .getCpeMatch()
                .getCpe23Uri());

        assertTrue(cnfNodes
                .get(2)
                .getOrOperands()
                .get(11)
                .isNegate());
    }

    @Test
    public void testStatementWithOr() throws IOException {
        Path path = Paths.get("src", "test", "resources", "assets", "cve", "entries", "applicability-or.json");
        DefNode rootNode = OBJECT_MAPPER.readValue(path.toFile(), DefNode.class);

        List<And> cnfNodes = StatementUtil.fromNVDApplicabilityStatement(rootNode).getAndOperands();

        assertEquals(1, cnfNodes.size());
        assertEquals("cpe:2.3:h:juniper:srx100:-:*:*:*:*:*:*:*", cnfNodes
                .get(0)
                .getOrOperands()
                .get(0)
                .getFactRef()
                .getCpeMatch()
                .getCpe23Uri());

        assertFalse(cnfNodes
                .get(0)
                .getOrOperands()
                .get(19)
                .isNegate());
    }

    @Test
    public void testStatementWithSingle() throws IOException {
        Path path = Paths.get("src", "test", "resources", "assets", "cve", "entries", "applicability-single.json");
        DefNode rootNode = OBJECT_MAPPER.readValue(path.toFile(), DefNode.class);

        List<And> cnfNodes = StatementUtil.fromNVDApplicabilityStatement(rootNode).getAndOperands();

        assertEquals(1, cnfNodes.size());
        assertEquals("cpe:2.3:a:troglobit:pimd:2.1.5:*:*:*:*:*:*:*", cnfNodes
              .get(0)
              .getOrOperands()
              .get(0)
              .getFactRef()
              .getCpeMatch()
              .getCpe23Uri());

        assertTrue(cnfNodes
              .get(0)
              .getOrOperands()
              .get(0)
              .isNegate());
    }
}
