import unittest
import random
from shamir_secret_sharing import ShamirSecretSharing, simulate_dkg, PRIME

class TestShamirSecretSharing(unittest.TestCase):
    def test_secret_reconstruction(self):
        """Test that the secret can be reconstructed with the minimum number of shares."""
        sss = ShamirSecretSharing(threshold=3, num_shares=5)
        secret = 123456789
        coefficients = sss.generate_polynomial(secret)
        shares = sss.generate_shares(coefficients)
        # Reconstruct with all shares
        reconstructed_secret = sss.reconstruct_secret(shares)
        self.assertEqual(secret, reconstructed_secret)
        # Reconstruct with minimum shares
        minimal_shares = {1: shares[1], 2: shares[2], 3: shares[3]}
        reconstructed_secret = sss.reconstruct_secret(minimal_shares)
        self.assertEqual(secret, reconstructed_secret)

    def test_insufficient_shares(self):
        """Test that the secret cannot be reconstructed with fewer than the threshold number of shares."""
        sss = ShamirSecretSharing(threshold=3, num_shares=5)
        secret = 123456789
        coefficients = sss.generate_polynomial(secret)
        shares = sss.generate_shares(coefficients)
        # Reconstruct with fewer than threshold shares
        insufficient_shares = {1: shares[1], 2: shares[2]}
        with self.assertRaises(ValueError):
            sss.reconstruct_secret(insufficient_shares)

    def test_commitment_scheme(self):
        """Test that the commitment scheme works correctly."""
        sss = ShamirSecretSharing(threshold=3, num_shares=5)
        secret = 123456789
        coefficients = sss.generate_polynomial(secret)
        commitment = sss.generate_commitment(coefficients)
        # Verify the commitment
        self.assertTrue(sss.verify_commitment(coefficients, commitment))
        # Test with incorrect coefficients
        fake_coefficients = [secret] + [random.randint(1, PRIME - 1) for _ in range(sss.threshold - 1)]
        self.assertFalse(sss.verify_commitment(fake_coefficients, commitment))

    def test_dkg_simulation(self):
        """Test the DKG simulation."""
        threshold = 3
        num_participants = 5
        # Simulate DKG
        simulate_dkg(threshold, num_participants)
        # No assertion here; just ensure the simulation runs without errors

if __name__ == "__main__":
    unittest.main()