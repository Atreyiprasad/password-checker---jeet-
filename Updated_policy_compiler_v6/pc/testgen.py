"""Deterministic test-case generator for the batch runner. Produces (category, password, expected) tuples.
expected = 'weak' (a good policy should reject it), 'strong' (a good policy should accept it) or None (no opinion).
These are test fixtures, not secrets."""
import random

COMMON = ["password", "123456", "12345678", "qwerty", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon", "football", "baseball",
          "sunshine", "princess", "master", "shadow", "superman", "trustno1", "abc123", "passw0rd", "login", "hello123", "starwars", "whatever", "freedom"]
LEET = ["P@ssw0rd", "P@ssword1", "Passw0rd!", "W3lcome1", "Adm1n123", "L3tm31n!", "Dr@gon123", "Iloveyou1!", "Sunsh1ne!", "Qwerty123!", "Pa$$w0rd", "Welc0me@1"]
KEYBOARD = ["qwertyuiop", "asdfghjkl", "zxcvbnm123", "1qaz2wsx", "qazwsxedc", "qwerty12345", "!QAZ2wsx", "1q2w3e4r5t", "poiuytrewq", "mnbvcxz987"]
SEQ = ["abcdefgh", "abcd1234", "12345678", "98765432", "aaaaaaaa", "11111111", "aaaa1111", "Abcdefg1!", "zzzzzzzz9", "0987654321", "abababab", "xyzxyzxyz"]
NAMES = ["Rocky", "Priyanka", "Sachin", "Rahul", "Sunita", "Arjun", "Ananya", "Vikram", "Meera", "Kabir", "Ishaan", "Tanvi", "Rohan", "Kavya"]
PLACES = ["Mumbai", "Delhi", "Pune", "Goa", "Jaipur", "London", "Paris", "Tokyo", "Chennai", "Kolkata", "Dubai", "Berlin"]
THINGS = ["Cricket", "Tiger", "Summer", "Winter", "Monsoon", "Liverpool", "Chelsea", "Pizza", "Coffee", "Rocket", "Cheetah", "Mango"]
SYMS = "!@#$%&*"
WORDS = ("anchor basket candle desert eagle forest garden harbor island jungle kettle lantern meadow nectar orchard pebble quartz river saddle "
         "timber umbrella velvet willow yonder zephyr amber bridge copper dolphin ember falcon glacier hammock indigo juniper kitten lagoon marble "
         "nutmeg ocean pepper quiver rabbit silver thunder unicorn violet walnut yarrow zenith blossom cactus dagger elbow ferret goblet").split()

def _rand_str(r, n, alphabet):
    return "".join(r.choice(alphabet) for _ in range(n))

def generate(count=150, seed=1, user="priya", company="acme"):
    r = random.Random(seed)
    ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    FULL = ALNUM + "!@#$%^&*()-_=+[]{};:,.?"
    # (category, expected, share, maker)
    def dict_year():
        w = r.choice(NAMES + PLACES + THINGS); return w + r.choice(SYMS) + str(r.choice([1985, 1990, 1998, 2001, 2015, 2023, 2024, 2025]))
    def two_words():
        a, b = r.choice(NAMES + THINGS), r.choice(PLACES + THINGS); return a + r.choice("@#_-") + b + str(r.randint(1, 99))
    def user_derived():
        return r.choice([user, user.capitalize(), user[::-1], user.upper()]) + r.choice(["", "!", "@", "#"]) + str(r.randint(1, 9999))
    def company_pw():
        return r.choice([company, company.capitalize(), company.upper()]) + r.choice(["@", "#", "_", "-"]) + str(r.choice([2023, 2024, 2025, 123, 1234]))
    def leet():
        return r.choice(LEET)
    def common():
        w = r.choice(COMMON); return r.choice([w, w.capitalize(), w + "1", w + "!", w + "123"])
    def short():
        return _rand_str(r, r.randint(4, 7), ALNUM)
    def passphrase():
        return "-".join(r.choice(WORDS) for _ in range(4)) if r.random() < .6 else " ".join(r.choice(WORDS) for _ in range(4))
    def random_strong():
        return _rand_str(r, r.randint(14, 22), FULL)
    def random_medium():
        return _rand_str(r, r.randint(9, 11), ALNUM)
    def long_pw():
        return _rand_str(r, r.randint(70, 140), FULL)
    def unicode_pw():
        return r.choice(["पासवर्ड", "üb3rSäure", "密码Pass2024!", "caféLaté#77"]) + _rand_str(r, r.randint(0, 6), ALNUM)
    plan = [("common", "weak", 9, common), ("leet-common", "weak", 7, leet), ("keyboard-walk", "weak", 6, lambda: r.choice(KEYBOARD)),
            ("sequence-repeat", "weak", 7, lambda: r.choice(SEQ)), ("too-short", "weak", 7, short), ("word+year", "weak", 10, dict_year),
            ("two-words+digits", "weak", 8, two_words), ("username-based", "weak", 6, user_derived), ("company-word", "weak", 5, company_pw),
            ("passphrase", "strong", 10, passphrase), ("random-strong", "strong", 12, random_strong), ("random-medium", None, 7, random_medium),
            ("very-long", "strong", 3, long_pw), ("unicode", None, 3, unicode_pw)]
    total = sum(p[2] for p in plan)
    cases = []
    for cat, exp, share, mk in plan:
        n = max(2, round(count * share / total))
        for _ in range(n):
            cases.append((cat, mk(), exp))
    r.shuffle(cases)
    while len(cases) > count: cases.pop()
    while len(cases) < count: cases.append(("random-strong", random_strong(), "strong"))
    return cases
