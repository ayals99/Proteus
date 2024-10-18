import z3
from z3 import *

special_chars = ['&', '|', '!', '(', ')', '=', '<', '>']


def find_infix_exp(string_exp):
    ee = str(string_exp).strip().replace("\n", "").replace(" ", "")
    var_name = ""
    exp_list = []
    for i in range(len(ee)):
        if ee[i] not in special_chars:
            var_name += str(ee[i])
            if i == len(ee) - 1 and var_name != "":
                exp_list.append(var_name)
        else:
            if var_name != "":
                exp_list.append(var_name)
            var_name = ""
            if ee[i - 1] == '!' and ee[i] == '=':
                exp_list.append("!=")
            elif ee[i - 1] == '<' and ee[i] == '=':
                exp_list.append("<=")
            elif ee[i - 1] == '>' and ee[i] == '=':
                exp_list.append(">=")
            elif ee[i - 1] == '=' and ee[i] == '=':
                exp_list.append("==")
            elif ee[i] == "!" and ee[i + 1] == "=":
                continue
            elif ee[i] == ">" and ee[i + 1] == "=":
                continue
            elif ee[i] == "<" and ee[i + 1] == "=":
                continue
            elif ee[i] == "=" and ee[i + 1] == "=":
                continue
            else:
                exp_list.append(ee[i])

    return exp_list


def find_postfix_exp(infix_exp):
    stack = []
    operators = ['&', '|', '!=', '(', ')', '==', '<', '>', '>=', '<=']
    precedence = {'!': 1, '!=': 2, '==': 2, '>=': 2, '<=': 2, '>': 2, '<': 2, '&': 3, '|': 4}
    postfix_exp = []

    for i in range(len(infix_exp)):
        if infix_exp[i] not in operators:
            postfix_exp.append(infix_exp[i])
            continue

        if infix_exp[i] == '(':
            stack.append(infix_exp[i])
            continue

        if infix_exp[i] == ')':
            while len(stack) != 0 and stack[-1] != '(':
                postfix_exp.append(stack.pop())
            stack.pop()
            continue

        if infix_exp[i] in operators:
            if len(stack) == 0 or stack[-1] == '(':
                stack.append(infix_exp[i])
            else:
                while len(stack) != 0 and stack[-1] != '(' and precedence[infix_exp[i]] >= precedence[stack[-1]]:
                    postfix_exp.append(stack.pop())
                stack.append(infix_exp[i])

    while len(stack) != 0:
        postfix_exp.append(stack.pop())

    return postfix_exp


def evaluate_exp(postfix_exp):
    operators = {'!': 1, '!=': 2, '==': 2, '>=': 2, '<=': 2, '>': 2, '<': 2, '&': 3, '|': 4}
    stack = []
    for i in range(len(postfix_exp)):
        if postfix_exp[i] not in operators:
            if postfix_exp[i].isnumeric():
                stack.append(postfix_exp[i])
            else:
                stack.append(Int(str(postfix_exp[i])))
            continue
        else:
            if postfix_exp[i] == '&':
                a = stack.pop()
                b = stack.pop()
                c = And(b, a)
                stack.append(c)

            elif postfix_exp[i] == '|':
                a = stack.pop()
                b = stack.pop()
                c = Or(b, a)
                stack.append(c)

            elif postfix_exp[i] == '!':
                a = stack.pop()
                c = Not(a)
                stack.append(c)

            elif postfix_exp[i] == '=':
                a = stack.pop()
                b = stack.pop()
                c = Not(Xor(b, a))
                stack.append(c)

            elif postfix_exp[i] == "!=":
                a = stack.pop()
                b = stack.pop()
                c = Xor(b, a)
                stack.append(c)

            elif postfix_exp[i] == ">=":
                a = stack.pop()
                b = stack.pop()
                c = b >= a
                stack.append(c)

            elif postfix_exp[i] == "<=":
                a = stack.pop()
                b = stack.pop()
                c = b <= a
                stack.append(c)

            elif postfix_exp[i] == ">":
                a = stack.pop()
                b = stack.pop()
                c = b > a
                stack.append(c)

            elif postfix_exp[i] == "<":
                a = stack.pop()
                b = stack.pop()
                c = b < a
                stack.append(c)

            else:
                a = stack.pop()
                b = stack.pop()
                c = b == a
                stack.append(c)

    return stack.pop()


'''
is_subset_condition(a,b) : is a is a subset(stricter) condition of b?
if a is true, b is always true -> true 
'''


def is_subset_condition(to_be_checked, transition):
    # print(to_be_checked, transition)
    if to_be_checked == "" and transition == "":
        return True
    if to_be_checked == "":
        expr1 = True
    else:
        expr1 = evaluate_exp(find_postfix_exp(find_infix_exp(to_be_checked)))

    if transition == "":
        expr2 = True
    else:
        expr2 = evaluate_exp(find_postfix_exp(find_infix_exp(transition)))

    # print(to_be_checked)
    # print(expr1)
    # print(transition)
    # print(expr2)
    # print("-----")
    c = And(expr1, Not(expr2))
    s = Solver()
    s.add(c)
    if s.check() == z3.unsat:
        return True
    else:
        return False


def simplify_condition(expression):
    expr1 = evaluate_exp(find_postfix_exp(find_infix_exp(expression)))
    s = Solver()
    s.add(expr1)
    if s.check() == z3.sat:
        e = simplify(expr1)
        return e