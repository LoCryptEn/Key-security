import random
import time
import subprocess
import tempfile

def generate_random_256bit():
    """Generates a random 256-bit integer."""
    return random.getrandbits(256)

def montgomery_modular_multiplication(a, b, m):
    """Performs modular multiplication (a * b) % m."""
    return (a * b * pow((1<<256), -1 , m)) % m

def call_c_program(x, y):
    """Calls the compiled C program with x and y as inputs."""
    input_data = f"{x:064x}{y:064x}"
    result = subprocess.run(["./montgomery_mul_n256"], input=input_data, text=True, capture_output=True)
    return result.stdout.strip()

def main():
    num_tests = 1000  # Number of test iterations
    matches = 0      # Counter for matching results
    mismatches = 0   # Counter for mismatched results

    for i in range(num_tests):
        print(f"Test {i + 1}/{num_tests}")

        # Generate random 256-bit integers for x and y
        x = generate_random_256bit()
        y = generate_random_256bit()
        m = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        # Perform modular multiplication in Python
        python_result = montgomery_modular_multiplication(x, y, m)

        # Print Python result and execution time
        print(f"Python Result: 0x{python_result:064x}")

        # Call the C program to compute the result
        c_result = call_c_program(x, y)

        # Print C program result and execution time
        print(f"C Program Result: {c_result}")

        # Compare results
        if c_result == f"0x{python_result:064x}":
            print("Results match!")
            matches += 1
        else:
            print("Results do not match.")
            mismatches += 1

        print("-")

    # Summary of results
    print(f"\nSummary:")
    print(f"Matches: {matches}")
    print(f"Mismatches: {mismatches}")

if __name__ == "__main__":
    main()
