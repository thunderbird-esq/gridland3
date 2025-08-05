import os
import hashlib
import json

def generate_hashes():
    """
    Calculates the SHA256 hash for each plugin file in the plugins/ directory
    and saves them to data/integrity.json.
    """
    plugin_dir = 'plugins'
    hashes = {}

    print(f"Generating hashes for plugins in '{plugin_dir}'...")

    try:
        for filename in os.listdir(plugin_dir):
            filepath = os.path.join(plugin_dir, filename)
            # Only hash .py files, ignore __pycache__ and other files
            if filename.endswith('.py') and os.path.isfile(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        file_content = f.read()
                        sha256_hash = hashlib.sha256(file_content).hexdigest()
                        hashes[filename] = sha256_hash
                        print(f"  - {filename}: {sha256_hash}")
                except IOError as e:
                    print(f"Error reading file {filename}: {e}")
    except FileNotFoundError:
        print(f"Error: The directory '{plugin_dir}' was not found.")
        return

    output_file = os.path.join('data', 'integrity.json')

    # Ensure the data directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    try:
        with open(output_file, 'w') as f:
            json.dump(hashes, f, indent=4)
        print(f"\nSuccessfully generated and saved hashes to '{output_file}'")
    except IOError as e:
        print(f"Error writing to file {output_file}: {e}")

if __name__ == '__main__':
    generate_hashes()
