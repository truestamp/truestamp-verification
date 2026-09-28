# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Writes binary64.txt beside this script: JSON number literals and the binary64 value
nearest each, rounded to nearest with ties to even, as Python's float() reads them.

The generator reads every JSON number with a conversion of its own (Generator.Binary64,
in generator/lib/binary64.exs), and its known-answer check holds that conversion to this
file. CPython's float() is correctly rounded on every platform, so its answers come from
outside the generator. Run it from the repository root, then `task generate`:

    python3 generator/known_answers/binary64.py

The file's form: lines that begin with # are comments. Every other line is a literal, one
space and its answer: the 16 lowercase hex digits of the value's IEEE 754 bits, or
`overflow` when the literal rounds to an infinity. A run of one digit written `[d*n]`
stands for that digit n times, so a literal of 262,144 digits fits on a short line; the
literal, once expanded, is one number of RFC 8259's grammar.
"""

import os
import random
import re
import struct
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "binary64.txt")
REPEAT = re.compile(r"\[(\d)\*(\d+)\]")
GRAMMAR = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")

rng = random.Random(20260928)


def expand(literal):
    return REPEAT.sub(lambda m: m.group(1) * int(m.group(2)), literal)


def compress(literal):
    """Writes each run of more than 40 of one digit as [d*n]."""
    return re.sub(r"(\d)\1{40,}", lambda m: "[%s*%d]" % (m.group(1), len(m.group(0))), literal)


def answer(literal):
    text = expand(literal)
    assert GRAMMAR.fullmatch(text), literal[:80]
    value = float(text)
    if value in (float("inf"), float("-inf")):
        return "overflow"
    return struct.pack(">d", value).hex()


def bits_to_float(bits):
    return struct.unpack(">d", struct.pack(">Q", bits))[0]


def exact_digits(fraction):
    """A nonnegative Fraction whose denominator is a power of two, as (digits, exponent):
    the integer of its decimal digits and the power of ten that scales it, exactly."""
    num, den = fraction.numerator, fraction.denominator
    shift = den.bit_length() - 1
    assert den == 1 << shift
    return num * 5**shift, -shift


def spell(digits, exponent, negative=False, form=None):
    """digits x 10^exponent as a JSON literal, in plain or scientific form."""
    text = str(digits)
    if digits == 0:
        text, exponent = "0", 0
    form = form or rng.choice(["plain", "plain", "sci", "sci_upper", "sci_plus"])
    if form == "plain":
        if exponent >= 0:
            body = text + "0" * exponent
        else:
            places = -exponent
            if len(text) <= places:
                body = "0." + "0" * (places - len(text)) + text
            else:
                body = text[:-places] + "." + text[-places:]
    else:
        point = exponent + len(text) - 1
        mantissa = text[0] + ("." + text[1:] if len(text) > 1 else "")
        mark = "E" if form == "sci_upper" else "e"
        sign = "+" if form == "sci_plus" and point >= 0 else ""
        body = "%s%s%s%d" % (mantissa, mark, sign, point)
    return ("-" if negative else "") + body


def neighbours(x):
    """x and the next binary64 value above it, both positive and finite."""
    bits = struct.unpack(">Q", struct.pack(">d", x))[0]
    return x, bits_to_float(bits + 1)


def halfway_cases(x, lengths):
    """The halfway point between x and the value above it, and the points just above and
    just below it, each spelled with a tail of each length in `lengths`."""
    low, high = neighbours(x)
    if high == float("inf"):
        return []
    digits, exponent = exact_digits((Fraction(low) + Fraction(high)) / 2)
    out = [spell(digits, exponent)]
    for k in lengths:
        scale = 10 ** (k + 1)
        out.append(spell(digits * scale + 1, exponent - k - 1))
        out.append(spell(digits * scale - 1, exponent - k - 1))
    return out


def random_finite():
    while True:
        x = bits_to_float(rng.getrandbits(63))
        if x != float("inf") and x == x:
            return x


def random_normal(low, high):
    return 2.0 ** rng.randint(low, high) * (1 + rng.random())


def main():
    literals = []

    # Hand-picked edges: DBL_MAX and the overflow edge 2^1024 - 2^970, the smallest
    # subnormal and half of it, the smallest normal, J5's integer range, zeros, and
    # exponents far out of range.
    dbl_max = Fraction(2**1024 - 2**971)
    tie = Fraction(2**1024 - 2**970)
    literals += [
        "1.7976931348623157e308",
        "1.7976931348623158e308",
        "1.7976931348623158079e308",
        "1.797693134862315807e308",
        "1.797693134862315808e308",
        "1.7976931348623159e308",
        "-1.7976931348623158e308",
        "-1.7976931348623159e308",
        str(dbl_max.numerator),
        str(tie.numerator),
        str(tie.numerator - 1),
        str(tie.numerator + 1),
        str(tie.numerator - 1) + "." + "9" * 300,
        str(tie.numerator) + ".[0*500]1",
        "1e308",
        "1e309",
        "1e400",
        "-1e400",
        "1e-400",
        "-1e-400",
        "5e-324",
        "4.9406564584124654e-324",
        "2.4703282292062327e-324",
        "2.4703282292062328e-324",
        "-2.4703282292062328e-324",
        "2.2250738585072014e-308",
        "2.2250738585072011e-308",
        "2.2250738585072012e-308",
        "2.225073858507201136057409796709131975934819546351645648e-308",
        "9007199254740991",
        "9007199254740992",
        "9007199254740993",
        "9007199254740993.0000000000000000000000000000001",
        "9007199254740995",
        "18014398509481985",
        "1e16",
        "1e21",
        "999999999999999999999",
        "1e23",
        "8.98846567431158e307",
        "0",
        "-0",
        "0.0",
        "-0.0",
        "0e5",
        "0.000e-99999999999999999999",
        "0e99999999999999999999",
        "1e99999999999999999999",
        "-1e99999999999999999999",
        "1e-99999999999999999999",
        "-1e-99999999999999999999",
        "0.[0*400]1e400",
        "1[0*400]e-400",
        "123456789012345678901234567890e-10",
        "0.1",
        "0.2",
        "0.3",
        "37.7749",
        "-122.4194",
        "1e-7",
        "75.75960580580087",
        "1.0",
        "4.50",
        "2e-3",
        "333333333.33333329",
        "1E30",
        "0.000000000000000000000000001",
    ]
    for exponent in (-1075, -1074, -1023, -1022, -1, 0, 1, 52, 53, 1023):
        literals += halfway_cases(float(2.0**exponent), [0, 3, 40])
    literals += halfway_cases(bits_to_float(0x7FEFFFFFFFFFFFFE), [0, 5])

    # The crashers of macOS 27's strtod, and the 637-character spelling of 75.75960580580087.
    literals += [
        "9999999999999998.[9*315]0000000000000001",
        "9007199254740990.4[9*313]09928007452590095",
        "9223372036854776831.[9*174]0776627963145223168",
        "-9223372036854773248.[0*174]9223372036854773248",
    ]
    # That spelling is the halfway point below 75.75960580580087 and a final 1 above it.
    below = bits_to_float(struct.unpack(">Q", struct.pack(">d", 75.75960580580087))[0] - 1)
    digits, exponent = exact_digits((Fraction(below) + Fraction(75.75960580580087)) / 2)
    text = spell(digits, exponent, form="plain")
    literals.append(text + "0" * (636 - len(text)) + "1")
    fixed = len(literals)

    # Random finite values, in the shortest form that reads back.
    for _ in range(800):
        x = random_finite()
        literals.append(repr(x) if rng.random() < 0.5 else repr(-x))

    # Halfway points, and just above and below each: normals near 1, where the spelling is
    # short, normals across the range, subnormals, and values next to powers of two.
    for _ in range(500):
        x = random_normal(-60, 80)
        literals += halfway_cases(x, [0, rng.randint(1, 30), rng.randint(31, 120)])
    for _ in range(60):
        x = random_normal(-1022, 1022)
        literals += halfway_cases(x, [0, rng.randint(1, 30)])
    for _ in range(30):
        x = bits_to_float(rng.randint(1, (1 << 52) - 1))
        literals += halfway_cases(x, [rng.randint(1, 40)])
    for _ in range(60):
        k = rng.randint(-1021, 1022)
        literals += halfway_cases(2.0**k - 2.0 ** (k - 53), [7])

    # Exact values of doubles, with a tail above or below.
    for _ in range(80):
        if rng.random() < 0.8:
            x = random_normal(-1022, 1023)
        else:
            x = bits_to_float(rng.randint(1, 1 << 52))
        digits, exponent = exact_digits(Fraction(x))
        k = rng.randint(1, 120)
        literals.append(spell(digits * 10**k + 1, exponent - k))
        literals.append(spell(digits * 10**k - 1, exponent - k))

    # Random digit strings, 18 to 1,200 digits, across the whole range and past its ends.
    for _ in range(400):
        short = [rng.randint(18, 40)] * 4 + [rng.randint(41, 400)] * 3
        length = rng.choice(short + [rng.randint(801, 1200)])
        digits = rng.randint(10 ** (length - 1), 10**length - 1)
        point = rng.randint(-345, 330)
        literals.append(spell(digits, point - length))

    # Tokens of about 262,144 digits, written with runs.
    literals += [
        "4.5035996273704985[0*262000]1e15",
        "4.5035996273704985e15",
        "4.5035996273704984[9*262000]e15",
        "[9*262143]",
        "0.[0*262140]1",
        "1[0*262000]e-262000",
        "[1*262143]e-262130",
        "[3*262143]e-262143",
        "-[7*262143]e-262450",
        "1.[0*262000]1",
        "1.[0*262000]",
        "2.[2*262000]e-308",
        "4.9406564584124654[4*262000]e-324",
    ]
    half, exponent = exact_digits(Fraction(1, 2**1075))
    literals.append(spell(half, exponent, form="sci"))
    text = str(half)
    point = exponent + len(text) - 1
    literals.append("%s.%s[0*262000]1e%d" % (text[0], text[1:], point))
    literals.append("%s.%s4[9*262000]e%d" % (text[0], text[1:-1], point))

    # A sign on a third of the random ones.
    signed = []
    for index, literal in enumerate(literals):
        if index >= fixed and not literal.startswith("-") and rng.random() < 0.33:
            literal = "-" + literal
        signed.append(literal)

    seen = set()
    lines = [
        "# Copyright (c) 2026 Truestamp, Inc.",
        "# SPDX-License-Identifier: Apache-2.0",
        "#",
        "# Written by binary64.py from Python's float(); see that script for the form.",
    ]
    for literal in signed:
        literal = compress(literal)
        if literal in seen:
            continue
        seen.add(literal)
        lines.append("%s %s" % (literal, answer(literal)))

    with open(OUT, "w", encoding="ascii", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    print("wrote %d known answers to %s" % (len(lines) - 4, OUT))


if __name__ == "__main__":
    main()
