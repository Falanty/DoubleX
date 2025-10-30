// Calculation of operators using javascript

// add remaining operators
const operators = {
    '*': (a, b) => a * b,
    '*=': (a, b) => a * b,
    '+': (a, b) => a + b,
    '+=': (a, b) => a + b,
    '-': (a, b) => a - b,
    '-=': (a, b) => a - b,
    '/': (a, b) => a / b,
    '/=': (a, b) => a / b,
    '**': (a, b) => a ** b,
    '**=': (a, b) => a ** b,
    '%': (a, b) => a % b,
    '%=': (a, b) => a % b,
    '==': (a, b) => a == b,
    '===': (a, b) => a === b,
    '!=': (a, b) => a != b,
    '!==': (a, b) => a !== b,
    '>': (a, b) => a > b,
    '<': (a, b) => a < b,
    '>=': (a, b) => a >= b,
    '<=': (a, b) => a <= b,
    '&&': (a, b) => a && b,
    '||': (a, b) => a || b,
    '!': (a) => !a,
    '++': (a) => a++,
    '--': (a) => a--,
};

/**
 * Calculation of prefix operator using javascript.
 *
 * @param operator
 * @param a
 * @param b
 * @returns {*}
 */
function prefixOperator(operator, a) {
    if (!operators[operator]) {
        return null
    }
    try {
        return operators[operator](a)
    } catch (error) {
        return error
    }
}

/**
 * Calculation of postfix operator using javascript.
 *
 * @param operator
 * @param a
 * @param b
 * @returns {*}
 */
function postfixOperator(operator, a) {
    if (!operators[operator]) {
        return null
    }
    try {
        return operators[operator](a)
    } catch (error) {
        return error
    }
}

/**
 * Calculation of infix operator using javascript.
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
