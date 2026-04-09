from datetime import datetime
import os


# Get the current year dynamically
year = datetime.now().year

# Copyright text to be added at the top of .py files
COPYRIGHT_NOTICE = f"""# Copyright (c) {year} The BitAiir Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""

def add_copyright_to_file(file_path: str) -> None:
    """
    Adds a copyright notice at the top of a given Python file, 
    if it's not already present.

    Parameters:
        file_path (str): Path to the Python file where the copyright 
                         notice should be added.
    
    Returns:
        None
    """
    try:
        # Open the file in read mode to check its contents
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.readlines()

        # Check if the copyright notice is already in the file
        if content and COPYRIGHT_NOTICE.splitlines()[0] in content[0]:
            print(f"Copyright already exists in: {file_path}")
            return

        # Add the copyright notice at the top of the file
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(COPYRIGHT_NOTICE + '\n')
            file.writelines(content)

        print(f"Copyright added to: {file_path}")
    except Exception as e:
        # Handle potential errors during file operations
        print(f"Error processing the file {file_path}: {e}")

def add_copyright_to_folder(folder_path: str) -> None:
    """
    Recursively adds the copyright notice to all Python files
    in a specified folder and its subfolders.

    Parameters:
        folder_path (str): Path to the folder to process. All .py files 
                           within this folder and subfolders will be updated.
    
    Returns:
        None
    """
    for root, _, files in os.walk(folder_path):
        for file in files:
            # Check if the file has a .py extension
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                add_copyright_to_file(file_path)


if __name__ == "__main__":
    # Define the root folder containing Python files to process
    src_folder = "src"

    # Verify if the folder exists before processing
    if os.path.exists(src_folder):
        add_copyright_to_folder(src_folder)
    else:
        print(f"The folder '{src_folder}' was not found.")
