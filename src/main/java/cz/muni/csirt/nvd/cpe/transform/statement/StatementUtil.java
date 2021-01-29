package cz.muni.csirt.nvd.cpe.transform.statement;

import cz.muni.csirt.nvd.cpe.transform.statement.element.And;
import cz.muni.csirt.nvd.cpe.transform.statement.element.FactRef;
import cz.muni.csirt.nvd.cpe.transform.statement.element.Or;
import gov.nist.nvd.feed.cve.DefCpeMatch;
import gov.nist.nvd.feed.cve.DefNode;
import org.apache.commons.lang3.BooleanUtils;
import org.logicng.formulas.Formula;
import org.logicng.formulas.FormulaFactory;
import org.logicng.formulas.Literal;

import java.util.*;
import java.util.stream.Collectors;

public class StatementUtil {

    private static final FormulaFactory F = new FormulaFactory();

    private static final String AND_OPERATOR = "AND";
    private static final String OR_OPERATOR = "OR";
    public static final String VAR_ATTR = "V";

    public static StatementCNF fromNVDApplicabilityStatement(DefNode rootNode) {
        HashMap<String, DefCpeMatch> reverse = new HashMap<>();
        Formula formula = constructFormula(rootNode, reverse);
        List<And> cnfFormula = convertToNodes(formula.cnf(), reverse);

        return new StatementCNF(cnfFormula, rootNode);
    }

    private static Formula constructFormula(DefNode parentNode, Map<String, DefCpeMatch> reverse) {
        String operator = parentNode.getOperator().toUpperCase();
        boolean negate = BooleanUtils.isTrue(parentNode.getNegate());

        int i = reverse.size();

        List<Formula> operands = new ArrayList<>();

        /*
         Although a node should never contain both CPEs and child nodes, we don't care.
         The code below works anyway, since the iteration block will not be entered, if the collection is empty.
        */

        for (DefCpeMatch cpeMatch : parentNode.getCpeMatch()) {
            String varName = VAR_ATTR + (i++ + 1);
            reverse.put(varName, cpeMatch);
            operands.add(F.variable(varName));
        }

        for (DefNode childNode : parentNode.getChildren()) {
            operands.add(constructFormula(childNode, reverse));
        }

        Formula result;

        if (Objects.equals(operator, AND_OPERATOR)) {
            result = F.and(operands);
        } else if (Objects.equals(operator, OR_OPERATOR)) {
            result = F.or(operands);
        } else {
            throw new IllegalArgumentException("Illegal operator.");
        }

        if (negate) {
            return F.not(result);
        }

        return result;
    }

    private static List<And> convertToNodes(Formula cnf, final Map<String, DefCpeMatch> reverse) {
        switch (cnf.type()) {
            case LITERAL:
                org.logicng.formulas.Literal l = (org.logicng.formulas.Literal) cnf;
                return Collections.singletonList(new And(Collections.singletonList(handleLiteral(l, reverse))));
            case OR:
                org.logicng.formulas.Or o = (org.logicng.formulas.Or) cnf;
                return Collections.singletonList(new And(handleOr(o, reverse)));
            case AND:
                org.logicng.formulas.And a = (org.logicng.formulas.And) cnf;
                return handleAnd(a, reverse);
            default:
                throw new IllegalArgumentException("Formula is not in CNF.");
        }
    }

    private static List<And> handleAnd(org.logicng.formulas.And operand, final Map<String, DefCpeMatch> reverse) {
        return operand
                .stream()
                .map(f -> new And(handleFormula(f, reverse)))
                .collect(Collectors.toList());
    }

    private static List<Or> handleFormula(Formula formula, final Map<String, DefCpeMatch> reverse) {
        switch (formula.type()) {
            case OR:
                org.logicng.formulas.Or o = (org.logicng.formulas.Or) formula;
                return handleOr(o, reverse);
            case LITERAL:
                Literal l = (Literal) formula;
                return Collections.singletonList(handleLiteral(l, reverse));
            default:
                throw new IllegalArgumentException("Formula is not in CNF.");
        }
    }

    private static List<Or> handleOr(org.logicng.formulas.Or or, final Map<String, DefCpeMatch> reverse) {
        return or
                .stream()
                .map(f -> handleLiteral((Literal) f, reverse)) // ClassCastException means that the formula was not CNF
                .collect(Collectors.toList());
    }

    private static Or handleLiteral(Literal literal, final Map<String, DefCpeMatch> reverse) {
        boolean negate = !literal.phase();
        DefCpeMatch cpeMatch = reverse.get(literal.name());
        FactRef factRef = new FactRef(cpeMatch);

        return new Or(negate, factRef);
    }
}
