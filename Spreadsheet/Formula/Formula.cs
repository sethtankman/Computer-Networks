// Skeleton written by Joe Zachary for CS 3500, January 2019

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using static Formulas.TokenType;

namespace Formulas
{
    /// <summary>
    /// Represents formulas written in standard infix notation using standard precedence
    /// rules.  Provides a means to evaluate Formulas.  Formulas can be composed of
    /// non-negative floating-point numbers, variables, left and right parentheses, and
    /// the four binary operator symbols +, -, *, and /.  (The unary operators + and -
    /// are not allowed.)
    /// </summary>
    public class Formula
    {
        private IEnumerable<Tuple<String, TokenType>> formulaTokens;
        /// <summary>
        /// Creates a Formula from a string that consists of a standard infix expression composed
        /// from non-negative floating-point numbers (using C#-like syntax for double/int literals), 
        /// variable symbols (a letter followed by zero or more letters and/or digits), left and right
        /// parentheses, and the four binary operator symbols +, -, *, and /.  White space is
        /// permitted between tokens, but is not required.
        /// 
        /// Examples of a valid parameter to this constructor are:
        ///     "2.5e9 + x5 / 17"
        ///     "(5 * 2) + 8"
        ///     "x*y-2+35/9"
        ///     
        /// Examples of invalid parameters are:
        ///     "_"
        ///     "-5.3"
        ///     "2 5 + 3"
        /// 
        /// If the formula is syntacticaly invalid, throws a FormulaFormatException with an 
        /// explanatory Message.
        /// </summary>
        public Formula(String formula)
        {
            Stack<Tuple<String, TokenType>> parenthStack = new Stack<Tuple<String, TokenType>>();
            formulaTokens = GetTokens(formula);
            Tuple<String, TokenType> lastToken = null;
            if (formulaTokens.GetEnumerator().MoveNext().ToString().Equals("False"))
            {
                throw new FormulaFormatException("No entry");
            }

            foreach (Tuple<String, TokenType> token in formulaTokens)
            {
                //handle unacceptable first tokens
                if (lastToken == null)
                {
                    if (token.Item2.Equals(RParen) || token.Item2.Equals(Oper))
                    {
                        throw new FormulaFormatException("Invalid First Token: " + token.Item1);
                    }
                }
                //handle invalid tokens
                if (token.Item2.Equals(Invalid))
                {
                    throw new FormulaFormatException("Invalid token: " + token.Item1);
                }
                //handle consecutive tokens
                if (lastToken != null && lastToken.Item2.Equals(token.Item2) &&
                    (lastToken.Item2.Equals(Oper) || lastToken.Item2.Equals(Var) ||
                    lastToken.Item2.Equals(Number)))
                {
                    throw new FormulaFormatException("Multiple consecutive invalidly placed tokens found");
                }
                //Ensure corrrect tokens after ( and operators
                if (lastToken != null && (lastToken.Item1.Equals("(") || lastToken.Item2.Equals(Oper)))
                {
                    if(token.Item2.Equals(Oper) || token.Item1.Equals(")"))
                    {
                        throw new FormulaFormatException("Invalid format");
                    }
                }
                //Ensure correct tokens after ), numbers, variables
                if (lastToken != null && (lastToken.Item2.Equals(Number) || 
                    lastToken.Item2.Equals(Var) || lastToken.Item1.Equals(")")))
                {
                    if(token.Item1.Equals("(") || token.Item2.Equals(Number) || token.Item2.Equals(Var))
                    {
                        throw new FormulaFormatException("Invalid format");
                    }
                }

                //handle parenthesis
                if (token.Item2.Equals(RParen) || token.Item2.Equals(LParen))
                {
                    if (token.Item2.Equals(LParen))
                    {
                        parenthStack.Push(token);
                    }
                    else if (parenthStack.Count > 0)
                    {
                        parenthStack.Pop();
                    }
                    else { throw new FormulaFormatException("Invalid Parenthesis"); }

                }
                lastToken = token;
            }
            if (parenthStack.Count != 0)
            {
                throw new FormulaFormatException("Invalid Parenthesis");
            }
            if (lastToken.Item2.Equals(Oper))
            {
                throw new FormulaFormatException("Invalid final token: Operator");
            }

        }
        /// <summary>
        /// Evaluates this Formula, using the Lookup delegate to determine the values of variables.  (The
        /// delegate takes a variable name as a parameter and returns its value (if it has one) or throws
        /// an UndefinedVariableException (otherwise).  Uses the standard precedence rules when doing the evaluation.
        /// 
        /// If no undefined variables or divisions by zero are encountered when evaluating 
        /// this Formula, its value is returned.  Otherwise, throws a FormulaEvaluationException  
        /// with an explanatory Message.
        /// </summary>
        public double Evaluate(Lookup lookup)
        {
            Stack<Tuple<String, TokenType>> numStack = new Stack<Tuple<String, TokenType>>();
            Stack<Tuple<String, TokenType>> operStack = new Stack<Tuple<String, TokenType>>();

            //add tokens to stacks
            foreach (Tuple<String, TokenType> token in formulaTokens)
            {
                //Adds Numbers and Variables
                if (token.Item2.Equals(Number) || token.Item2.Equals(Var))
                {
                    double value;
                    //Variable handler
                    if (token.Item2.Equals(Var))
                    {
                        try
                        {
                            value = lookup(token.Item1);
                        }
                        catch (UndefinedVariableException)
                        {
                            throw new FormulaEvaluationException(token.Item1);
                        }

                        var toPush = GetTokens(value + "").GetEnumerator();
                        toPush.MoveNext();

                        if (operStack.Count == 0)
                        {
                            numStack.Push(toPush.Current);
                            continue;
                        }

                        if (operStack.Peek().Item1.Equals("*") ||
                            operStack.Peek().Item1.Equals("/"))
                        {
                            double.TryParse(numStack.Pop().Item1, out double num1);

                            if (operStack.Peek().Item1.Equals("*"))
                            {
                                double product = num1 * value;
                                operStack.Pop();
                                toPush = GetTokens(product + "").GetEnumerator();
                                toPush.MoveNext();
                                numStack.Push(toPush.Current);
                            }
                            else if (operStack.Peek().Item1.Equals("/"))
                            {
                                double quotient = num1 / value;
                                operStack.Pop();
                                toPush = GetTokens(quotient + "").GetEnumerator();
                                toPush.MoveNext();
                                numStack.Push(toPush.Current);
                            }
                        }
                        else
                        {
                            numStack.Push(toPush.Current);
                            continue;
                        }
                        continue;
                    }

                    if (operStack.Count == 0)
                    {
                        numStack.Push(token);
                        continue;
                    }

                    if (operStack.Peek().Item1.Equals("*") ||
                        operStack.Peek().Item1.Equals("/"))
                    {
                        double.TryParse(numStack.Pop().Item1, out double num1);
                        double.TryParse(token.Item1, out double num2);

                        if (operStack.Peek().Item1.Equals("*"))
                        {
                            double product = num1 * num2;
                            operStack.Pop();
                            var toPush = GetTokens(product + "").GetEnumerator();
                            toPush.MoveNext();
                            numStack.Push(toPush.Current);
                        }
                        else if (operStack.Peek().Item1.Equals("/"))
                        {
                            double quotient = num1 / num2;
                            operStack.Pop();
                            var toPush = GetTokens(quotient + "").GetEnumerator();
                            toPush.MoveNext();
                            numStack.Push(toPush.Current);
                        }
                    }
                    else
                    {
                        numStack.Push(token);
                        continue;
                    }
                }


                //Handles + and -
                if (token.Item1.Equals("+") || token.Item1.Equals("-"))
                {
                    if (operStack.Count == 0)
                    {
                        operStack.Push(token);
                        continue;
                    }
                    if (operStack.Peek().Item1.Equals("+") || operStack.Peek().Item1.Equals("-"))
                    {
                        double.TryParse(numStack.Pop().Item1, out double num1);
                        double.TryParse(numStack.Pop().Item1, out double num2);
                        if (operStack.Peek().Item1.Equals("+"))
                        {
                            double sum = num1 + num2;
                            operStack.Pop();
                            var toPush = GetTokens(sum + "").GetEnumerator();
                            toPush.MoveNext();
                            numStack.Push(toPush.Current);
                        }
                        if (operStack.Peek().Item1.Equals("-"))
                        {
                            double difference = num1 - num2;
                            operStack.Pop();
                            var toPush = GetTokens(difference + "").GetEnumerator();
                            toPush.MoveNext();
                            numStack.Push(toPush.Current);
                        }
                    }
                    operStack.Push(token);
                    continue;
                }

                //Handles Left Parenthesis, * and /
                if (token.Item2.Equals(LParen) || token.Item1.Equals("*") || token.Item1.Equals("/"))
                {
                    operStack.Push(token);
                    continue;
                }

                //Handles Right Parenthesis
                if (token.Item2.Equals(RParen))
                {
                    //Addition and subtraction with parenthesis
                    if (operStack.Peek().Item1.Equals("+") || operStack.Peek().Item1.Equals("-"))
                    {
                        double.TryParse(numStack.Pop().Item1, out double num1);
                        double.TryParse(numStack.Pop().Item1, out double num2);
                        if (operStack.Peek().Item1.Equals("+"))
                        {
                            double sum = num2 + num1;
                            operStack.Pop();
                            var toPush = GetTokens(sum + "").GetEnumerator();
                            toPush.MoveNext();
                            numStack.Push(toPush.Current);
                        }
                        if (operStack.Peek().Item1.Equals("-"))
                        {
                            double difference = num2 - num1;
                            operStack.Pop();
                            var toPush = GetTokens(difference + "").GetEnumerator();
                            toPush.MoveNext();
                            numStack.Push(toPush.Current);
                        }
                        operStack.Pop();
                    }
                    //Multiplication and Division with parenthesis
                    else if (operStack.Peek().Item1.Equals("*") ||
                        operStack.Peek().Item1.Equals("/"))
                    {
                        double.TryParse(numStack.Pop().Item1, out double num1);
                        double.TryParse(numStack.Pop().Item1, out double num2);

                        if (operStack.Peek().Item1.Equals("*"))
                        {
                            double product = num1 * num2;
                            operStack.Pop();
                            var toPush = GetTokens(product + "").GetEnumerator();
                            toPush.MoveNext();
                            numStack.Push(toPush.Current);
                        }
                        else if (operStack.Peek().Item1.Equals("/"))
                        {
                            double quotient = num1 / num2;
                            operStack.Pop();
                            var toPush = GetTokens(quotient + "").GetEnumerator();
                            toPush.MoveNext();
                            numStack.Push(toPush.Current);
                        }
                        operStack.Pop();
                    }
                    else if (operStack.Peek().Item1.Equals("("))
                    {
                        operStack.Pop();
                        continue;
                    } else
                    {
                        numStack.Push(token);
                        continue;
                    }
                }

            }
            //Perform final operation if operStack is empty
            if (operStack.Count != 0)
            {
                double.TryParse(numStack.Pop().Item1, out double num1);
                double.TryParse(numStack.Pop().Item1, out double num2);
                if (operStack.Peek().Item1.Equals("+"))
                {
                    double sum = num2 + num1;
                    operStack.Pop();
                    var toPush = GetTokens(sum + "").GetEnumerator();
                    toPush.MoveNext();
                    numStack.Push(toPush.Current);
                }
                else if (operStack.Peek().Item1.Equals("-"))
                {
                    double difference = num2 - num1;
                    operStack.Pop();
                    var toPush = GetTokens(difference + "").GetEnumerator();
                    toPush.MoveNext();
                    numStack.Push(toPush.Current);
                }
                else if (operStack.Peek().Item1.Equals("*"))
                {
                    double product = num2 * num1;
                    operStack.Pop();
                    var toPush = GetTokens(product + "").GetEnumerator();
                    toPush.MoveNext();
                    numStack.Push(toPush.Current);
                }
                else if (operStack.Peek().Item1.Equals("/"))
                {
                    double quotient = num2 / num1;
                    operStack.Pop();
                    var toPush = GetTokens(quotient + "").GetEnumerator();
                    toPush.MoveNext();
                    numStack.Push(toPush.Current);
                }
            }
            double.TryParse(numStack.Pop().Item1, out double evaluation);
            return evaluation;
        }

        public double numCrunch(Stack<Tuple<String, TokenType>> nums, Stack<Tuple<String, TokenType>> opers)
        {
            double answer = 0;

            return answer;
        }

        /// <summary>
        /// Given a formula, enumerates the tokens that compose it.  Each token is described by a
        /// Tuple containing the token's text and TokenType.  There are no empty tokens, and no
        /// token contains white space.
        /// </summary>
        private static IEnumerable<Tuple<string, TokenType>> GetTokens(String formula)
        {
            // Patterns for individual tokens.
            String lpPattern = @"\(";
            String rpPattern = @"\)";
            String opPattern = @"[\+\-*/]";
            String varPattern = @"[a-zA-Z][0-9a-zA-Z]*";

            // NOTE:  I have added white space to this regex to make it more readable.
            // When the regex is used, it is necessary to include a parameter that says
            // embedded white space should be ignored.  See below for an example of this.
            String doublePattern = @"(?: \d+\.\d* | \d*\.\d+ | \d+ ) (?: e[\+-]?\d+)?";
            String spacePattern = @"\s+";

            // Overall token pattern.  It contains embedded white space that must be ignored when
            // it is used.  See below for an example of this.
            String tokenPattern = String.Format("({0}) | ({1}) | ({2}) | ({3}) | ({4}) | ({5}) | (.)",
                                            spacePattern, lpPattern, rpPattern, opPattern, varPattern, doublePattern);

            // Create a Regex for matching tokens.  Notice the second parameter to Split says 
            // to ignore embedded white space in the pattern.
            Regex r = new Regex(tokenPattern, RegexOptions.IgnorePatternWhitespace);

            // Look for the first match
            Match match = r.Match(formula);

            // Start enumerating tokens
            while (match.Success)
            {
                // Ignore spaces
                if (!match.Groups[1].Success)
                {
                    // Holds the token's type
                    TokenType type;

                    if (match.Groups[2].Success)
                    {
                        type = LParen;
                    }
                    else if (match.Groups[3].Success)
                    {
                        type = RParen;
                    }
                    else if (match.Groups[4].Success)
                    {
                        type = Oper;
                    }
                    else if (match.Groups[5].Success)
                    {
                        type = Var;
                    }
                    else if (match.Groups[6].Success)
                    {
                        type = Number;
                    }
                    else if (match.Groups[7].Success)
                    {
                        type = Invalid;
                    }
                    else
                    {
                        // We shouldn't get here
                        throw new InvalidOperationException("Regular exception failed in GetTokens");
                    }

                    // Yield the token
                    yield return new Tuple<string, TokenType>(match.Value, type);
                }

                // Look for the next match
                match = match.NextMatch();
            }
        }
    }

    /// <summary>
    /// Identifies the type of a token.
    /// </summary>
    public enum TokenType
    {
        /// <summary>
        /// Left parenthesis
        /// </summary>
        LParen,

        /// <summary>
        /// Right parenthesis
        /// </summary>
        RParen,

        /// <summary>
        /// Operator symbol
        /// </summary>
        Oper,

        /// <summary>
        /// Variable
        /// </summary>
        Var,

        /// <summary>
        /// Double literal
        /// </summary>
        Number,

        /// <summary>
        /// Invalid token
        /// </summary>
        Invalid
    };

    /// <summary>
    /// A Lookup method is one that maps some strings to double values.  Given a string,
    /// such a function can either return a double (meaning that the string maps to the
    /// double) or throw an UndefinedVariableException (meaning that the string is unmapped 
    /// to a value. Exactly how a Lookup method decides which strings map to doubles and which
    /// don't is up to the implementation of the method.
    /// </summary>
    public delegate double Lookup(string var);

    /// <summary>
    /// Used to report that a Lookup delegate is unable to determine the value
    /// of a variable.
    /// </summary>
    [Serializable]
    public class UndefinedVariableException : Exception
    {
        /// <summary>
        /// Constructs an UndefinedVariableException containing whose message is the
        /// undefined variable.
        /// </summary>
        /// <param name="variable"></param>
        public UndefinedVariableException(String variable)
            : base(variable)
        {
        }
    }

    /// <summary>
    /// Used to report syntactic errors in the parameter to the Formula constructor.
    /// </summary>
    [Serializable]
    public class FormulaFormatException : Exception
    {
        /// <summary>
        /// Constructs a FormulaFormatException containing the explanatory message.
        /// </summary>
        public FormulaFormatException(String message) : base(message)
        {
        }
    }

    /// <summary>
    /// Used to report errors that occur when evaluating a Formula.
    /// </summary>
    [Serializable]
    public class FormulaEvaluationException : Exception
    {
        /// <summary>
        /// Constructs a FormulaEvaluationException containing the explanatory message.
        /// </summary>
        public FormulaEvaluationException(String message) : base(message)
        {
        }
    }
}
