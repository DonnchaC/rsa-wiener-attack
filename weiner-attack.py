"""
Created on Dec 14, 2011

@author: pablocelayes
"""

import sys

import ContinuedFractions
import Arithmetic
import RSAvulnerableKeyGenerator


def hack_RSA(e, n):
    """
    Finds d knowing (e, n) applying the Wiener continued fraction attack
    """

    frac = ContinuedFractions.rational_to_contfrac(e, n)
    convergents = ContinuedFractions.convergents_from_contfrac(frac)

    for (k, d) in convergents:
        # Check if d is actually the key
        if k != 0 and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = n - phi + 1

            # Check if the equation x^2 - s*x + n = 0 has integer roots
            discr = s * s - 4 * n
            if(discr >= 0):
                t = Arithmetic.is_perfect_square(discr)
                if t != -1 and (s + t) % 2 == 0:
                    return d
    return None


def test_hack_RSA():
    """
    Test Weiner's attack on a set of known vulnerable keys
    """

    for i in range(0, 5):
        e, n, d = RSAvulnerableKeyGenerator.generateKeys(1024)
        print("(e, n) is (", e, ", ", n, ")")
        print("d = ", d)

        hacked_d = hack_RSA(e, n)

        if d == hacked_d:
            print("Attack worked!")
        else:
            print("Attack failed!")

        print("d = ", d, ", hacked_d = ", hacked_d)
        print("-------------------------")


def parse_cmd_args():
    """
    Parses and returns command line arguments.
    """

    parser = argparse.ArgumentParser(
        description="%s uses Weiner's attack to recover RSA private keys" %
        sys.argv[0])

    parser.add_argument("--run-tests", action='store_true', default=False,
                        help="Run tests of Weiner's attack")

    parser.add_argument("public_key", type=argparse.FileType("r"), nargs="?",
                        default=None,  help="RSA public key in PEM format to "
                        "attack")

    args = parser.parse_args()

    # Show help if not arguments or flags specified
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    return args

if __name__ == '__main__':
    from Crypto.PublicKey import RSA
    import argparse

    args = parse_cmd_args()

    if args.run_tests:
        print("Testing Wiener Attack")
        test_hack_RSA()
        sys.exit(0)

    if args.public_key:
        public_key = RSA.importKey(args.public_key.read())

        # Try performing Weiner's attack
        hacked_d = hack_RSA(public_key.e, public_key.n)

        if hacked_d:
            print("Succesfully recovered d!")
            private_key = RSA.construct((public_key.n, public_key.e, hacked_d))
            print(private_key.exportKey('PEM').decode('utf-8'))

        else:
            print("Could not recovery the private key.")

        sys.exit(0)
