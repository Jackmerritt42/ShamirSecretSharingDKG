# ShamirSecretSharingDKG

A Python implementation of **Shamir's Secret Sharing (SSS)** and the **Boneh-Franklin Distributed Key Generation (DKG)** protocol. This project explores the practical and theoretical implications of secure distributed key management, with a focus on threshold cryptography and fault tolerance.

## Features

- **Shamir's Secret Sharing (SSS):**
  - Split a secret into multiple shares.
  - Reconstruct the secret from a subset of shares using Lagrange interpolation.
  - Polynomial commitment scheme for secure share verification.

- **Boneh-Franklin DKG Protocol:**
  - Simulate multiple participants in a distributed key generation process.
  - Generate a shared secret key and public key.
  - Visualize the protocol steps, including share distribution and polynomial curves.

- **Fault Tolerance:**
  - Detect and exclude malicious or non-cooperative participants.
  - Use Feldman's Verifiable Secret Sharing (VSS) for secure share verification.

- **Visualizations:**
  - Network graph of participants and their connections.
  - Polynomial curves used in secret sharing.
  - Share distribution across participants.

## Getting Started

### Prerequisites

- Python 3.8 or higher.
- Required Python libraries: `cryptography`, `numpy`, `matplotlib`, `networkx`, and `ecdsa`.

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Jackmerritt42/ShamirSecretSharingDKG.git
   cd ShamirSecretSharingDKG
Create a virtual environment and activate it:

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
Install the required dependencies:

pip install -r requirements.txt
Usage
Run the DKG simulation:


python shamir_secret_sharing.py
The simulation will:

Generate a shared secret key.

Visualize the participant network, polynomial curves, and share distribution.

Handle malicious participants (if any) and reconstruct the secret.

Example Output
Shared Secret Key: 123456789

Visualizations:

A network graph showing participants and their connections.

Polynomial curves for each participant.

A scatter plot of shares distributed by each participant.

Code Structure
shamir_secret_sharing.py:

Core implementation of Shamir's Secret Sharing and the Boneh-Franklin DKG protocol.

Includes classes for ShamirSecretSharing and Participant.

Functions for visualization and simulation.

test_shamir_secret_sharing.py:

Unit tests for the SSS and DKG implementations.

README.md:

Project documentation (this file).

requirements.txt:

List of Python dependencies.


Acknowledgments
Shamir's Secret Sharing: Based on the work of Adi Shamir.

Boneh-Franklin DKG Protocol: Inspired by the paper "Efficient Generation of Shared RSA Keys" by Dan Boneh and Matthew Franklin.

Visualizations: Powered by matplotlib and networkx.