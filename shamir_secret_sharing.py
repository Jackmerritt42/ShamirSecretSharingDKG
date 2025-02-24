import random
import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Define a large prime number for the finite field
PRIME = 2**256 - 2**32 - 977  # secp256k1 prime

class ShamirSecretSharing:
    def __init__(self, threshold, num_shares):
        """
        Initialize the ShamirSecretSharing class.
        Args:
            threshold (int): Minimum number of shares required to reconstruct the secret.
            num_shares (int): Total number of shares to generate.
        """
        self.threshold = threshold
        self.num_shares = num_shares

    def generate_polynomial(self, secret):
        """
        Generate a random polynomial of degree (threshold - 1) with the secret as the constant term.
        Args:
            secret (int): The secret to be shared.
        Returns:
            list: A list of polynomial coefficients.
        """
        coefficients = [secret] + [random.randint(1, PRIME - 1) for _ in range(self.threshold - 1)]
        return coefficients

    def evaluate_polynomial(self, coefficients, x):
        """
        Evaluate the polynomial at a given point x.
        Args:
            coefficients (list): The polynomial coefficients.
            x (int): The point at which to evaluate the polynomial.
        Returns:
            int: The result of the polynomial evaluation.
        """
        result = 0
        for coeff in reversed(coefficients):
            result = (result * x + coeff) % PRIME
        return result

    def generate_shares(self, coefficients):
        """
        Generate shares by evaluating the polynomial at distinct points.
        Args:
            coefficients (list): The polynomial coefficients.
        Returns:
            dict: A dictionary of shares, where keys are participant IDs and values are share values.
        """
        shares = {}
        for i in range(1, self.num_shares + 1):
            shares[i] = self.evaluate_polynomial(coefficients, i)
        return shares

    def reconstruct_secret(self, shares):
        """
        Reconstruct the secret using Lagrange interpolation.
        Args:
            shares (dict): A dictionary of shares, where keys are participant IDs and values are share values.
        Returns:
            int: The reconstructed secret.
        """
        x = list(shares.keys())
        y = list(shares.values())
        secret = 0
        for i in range(len(x)):
            numerator, denominator = 1, 1
            for j in range(len(x)):
                if i != j:
                    numerator = (numerator * (-x[j])) % PRIME
                    denominator = (denominator * (x[i] - x[j])) % PRIME
            lagrange_coeff = numerator * pow(denominator, PRIME - 2, PRIME)  # Modular inverse
            secret = (secret + y[i] * lagrange_coeff) % PRIME
        return secret

# Example usage
if __name__ == "__main__":
    sss = ShamirSecretSharing(threshold=3, num_shares=5)
    secret = 123456789  # Example secret
    coefficients = sss.generate_polynomial(secret)
    shares = sss.generate_shares(coefficients)
    print("Shares:", shares)
    reconstructed_secret = sss.reconstruct_secret(shares)
    print("Reconstructed Secret:", reconstructed_secret)