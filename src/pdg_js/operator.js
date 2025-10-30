// Calculation of operators using javascript

// add remaining operators
const operators = {
  '*': (x, y) => x * y,
  '*=': (x, y) => x * y,
};

/**
 * Calculation of operator using javascript.
 *
 * @param operator
 * @param a
 * @param b
 * @returns {*}
 */
function infixOperator(operator, a, b) {
    if (!operators[operator]) {
        return null
    }
    try {
        return operators[operator](a, b)
    } catch (error) {
        return error
    }
}
