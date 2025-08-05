import os
import hashlib
import json

def generate_hashes():
    """
    Generates SHA256 hashes for all plugin files and stores them in a JSON file.
    """
    plugin_dir = 'plugins'
    hashes = {}

    # Ensure the plugin directory exists
    if not os.path.isdir(plugin_dir):
        print(f"Error: Plugin directory '{plugin_dir}' not found.")
        return

    for filename in os.listdir(plugin_dir):
        if filename.endswith('.py') and filename != '__init__.py':
            filepath = os.path.join(plugin_dir, filename)
            try:
                with open(filepath, 'rb') as f:
                    file_content = f.read()
                    sha256_hash = hashlib.sha256(file_content).hexdigest()
                    hashes[filename] = sha256_hash
                    print(f"Hashed {filename}: {sha256_hash}")
            except IOError as e:
                print(f"Error reading file {filepath}: {e}")

    # Ensure the data directory exists
    data_dir = 'data'
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    output_path = os.path.join(data_dir, 'integrity.json')
    try:
        with open(output_path, 'w') as f:
            json.dump(hashes, f, indent=4)
        print(f"\nSuccessfully wrote hashes to {output_path}")
    except IOError as e:
        print(f"Error writing to file {output_path}: {e}")

if __name__ == '__main__':
    generate_hashes()
