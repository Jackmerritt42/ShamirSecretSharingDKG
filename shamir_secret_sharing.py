import random
from cryptography.hazmat.primitives import hashes
import matplotlib.pyplot as plt
import networkx as nx

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
        Raises:
            ValueError: If the number of shares is less than the threshold.
        """
        if len(shares) < self.threshold:
            raise ValueError("Insufficient shares to reconstruct the secret")
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

    def generate_commitment(self, coefficients):
        """
        Generate a commitment for the polynomial coefficients using a cryptographic hash function.
        Args:
            coefficients (list): The polynomial coefficients.
        Returns:
            bytes: The commitment (hash of the coefficients).
        """
        # Convert coefficients to a byte string
        coefficient_bytes = b"".join(coeff.to_bytes(32, "big") for coeff in coefficients)
        # Hash the coefficients using SHA-256
        digest = hashes.Hash(hashes.SHA256())
        digest.update(coefficient_bytes)
        return digest.finalize()

    def verify_commitment(self, coefficients, commitment):
        """
        Verify that the polynomial coefficients match the commitment.
        Args:
            coefficients (list): The polynomial coefficients.
            commitment (bytes): The original commitment.
        Returns:
            bool: True if the coefficients match the commitment, False otherwise.
        """
        # Recompute the commitment
        new_commitment = self.generate_commitment(coefficients)
        # Compare the recomputed commitment with the original
        return new_commitment == commitment


class Participant:
    def __init__(self, participant_id, threshold, num_participants):
        """
        Initialize a participant in the DKG protocol.
        Args:
            participant_id (int): The ID of the participant.
            threshold (int): The threshold for secret sharing.
            num_participants (int): The total number of participants.
        """
        self.id = participant_id
        self.threshold = threshold
        self.num_participants = num_participants
        self.sss = ShamirSecretSharing(threshold, num_participants)
        self.secret = random.randint(1, PRIME - 1)  # Participant's secret
        self.coefficients = self.sss.generate_polynomial(self.secret)
        self.commitment = self.sss.generate_commitment(self.coefficients)
        self.shares_received = {}  # Stores shares received from other participants

    def distribute_shares(self):
        """
        Distribute shares to all participants.
        Returns:
            dict: A dictionary of shares, where keys are participant IDs and values are share values.
        """
        return self.sss.generate_shares(self.coefficients)

    def receive_share(self, sender_id, share):
        """
        Receive a share from another participant.
        Args:
            sender_id (int): The ID of the participant sending the share.
            share (int): The share value.
        """
        self.shares_received[sender_id] = share

    def verify_shares(self, commitments):
        """
        Verify the shares received from other participants.
        In a real DKG implementation, this would use Feldman's VSS or Pedersen's DKG
        to verify shares cryptographically.
        
        For this simplified implementation, we'll check that shares are within valid range.
        
        Args:
            commitments (dict): A dictionary of commitments, where keys are participant IDs and values are commitments.
        Returns:
            bool: True if all shares are valid, False otherwise.
        """
        # In a real implementation, you would verify each share using a verification technique
        # that doesn't require knowing the coefficients
        # For educational purposes, we'll implement a simplified check
        
        for sender_id, share in self.shares_received.items():
            # Ensure the share is within the valid range
            if not (0 <= share < PRIME):
                print(f"Participant {self.id}: Invalid share value from Participant {sender_id}")
                print(f"Commitment: {commitments[sender_id].hex()}")
                return False
        
        return True

    def compute_share_of_secret_key(self):
        """
        Compute the participant's share of the secret key.
        Returns:
            int: The participant's share of the secret key.
        """
        # In the simplest form, this is the sum of all shares received
        return sum(self.shares_received.values()) % PRIME

def visualize_network(participants):
    """
    Visualize the network of participants as a graph.
    Args:
        participants (list): A list of Participant objects.
    """
    G = nx.DiGraph()
    for participant in participants:
        G.add_node(participant.id, label=f"Participant {participant.id}")
        for receiver_id in range(1, len(participants) + 1):
            if receiver_id != participant.id:  # Don't draw self-loops
                G.add_edge(participant.id, receiver_id)
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_color="lightblue", node_size=2000, font_size=10, font_weight="bold")
    plt.title("Participant Network")
    plt.show()


def visualize_polynomial(coefficients, x_range=range(1, 6)):
    """
    Visualize the polynomial used in Shamir's Secret Sharing.
    Args:
        coefficients (list): The polynomial coefficients.
        x_range (range): The range of x values to plot.
    """
    x_values = list(x_range)
    # Use a simplified approach for visualization - actual values are too large for plotting
    scaled_coeffs = [coeff % 1000 for coeff in coefficients]  # Scale down coefficients for visualization
    y_values = [sum(coeff * (x ** i) for i, coeff in enumerate(scaled_coeffs)) % 1000 for x in x_values]
    plt.figure()
    plt.plot(x_values, y_values, marker="o")
    plt.title("Polynomial Curve (Scaled for Visualization)")
    plt.xlabel("x")
    plt.ylabel("P(x) mod 1000")
    plt.grid(True)
    plt.show()


def visualize_shares(participants):
    """
    Visualize the shares distributed by each participant.
    Args:
        participants (list): A list of Participant objects.
    """
    plt.figure()
    for participant in participants:
        shares = participant.distribute_shares()
        x_values = list(shares.keys())
        # Scale down share values for visualization
        y_values = [share % 1000 for share in shares.values()]
        plt.scatter(x_values, y_values, label=f"Participant {participant.id}")
    plt.title("Shares Distributed by Participants (Scaled for Visualization)")
    plt.xlabel("Participant ID")
    plt.ylabel("Share Value mod 1000")
    plt.legend()
    plt.grid(True)
    plt.show()


def simulate_dkg(threshold, num_participants):
    """
    Simulate the Distributed Key Generation protocol.
    Args:
        threshold (int): The threshold for secret sharing.
        num_participants (int): The total number of participants.
    """
    # Create participants
    participants = [Participant(i + 1, threshold, num_participants) for i in range(num_participants)]

    # Step 1: Distribute shares
    for sender in participants:
        shares = sender.distribute_shares()
        for receiver_id, share in shares.items():
            if 1 <= receiver_id <= num_participants:  # Ensure valid participant ID
                participants[receiver_id - 1].receive_share(sender.id, share)

    # Step 2: Verify shares
    commitments = {p.id: p.commitment for p in participants}
    all_valid = True
    for participant in participants:
        if not participant.verify_shares(commitments):
            print(f"Participant {participant.id} detected invalid shares!")
            all_valid = False
    
    if not all_valid:
        print("DKG process failed due to invalid shares!")
        return

    # Step 3: Each participant computes their share of the secret key
    shares_of_secret_key = {p.id: p.compute_share_of_secret_key() for p in participants}
    
    # In a real application, the secret key would remain distributed
    # For demonstration, we'll show that we can reconstruct it with enough shares
    if threshold <= len(shares_of_secret_key):
        # Use the first 'threshold' shares to reconstruct
        subset_shares = {k: shares_of_secret_key[k] for k in list(shares_of_secret_key.keys())[:threshold]}
        sss = ShamirSecretSharing(threshold, num_participants)
        reconstructed_key = sss.reconstruct_secret(subset_shares)
        print(f"Reconstructed Secret Key: {reconstructed_key}")
    
    print("DKG completed successfully!")

    # Step 4: Visualize the process (if matplotlib is installed)
    try:
        visualize_network(participants)
        # Only visualize the first participant's polynomial to keep it simple
        visualize_polynomial(participants[0].coefficients)
        visualize_shares(participants)
    except Exception as e:
        print(f"Visualization skipped: {e}")


# Example usage
if __name__ == "__main__":
    print("Starting DKG simulation...")
    simulate_dkg(threshold=3, num_participants=5)