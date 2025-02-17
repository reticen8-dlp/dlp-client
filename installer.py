import os

def get_user_input(prompt, default=""):
    """Get user input with a default option."""
    user_input = input(f"{prompt} (Default: {default}): ").strip()
    return user_input if user_input else default

def generate_settings():
    """Ask user for settings and generate settings.py dynamically."""
    
    print("\n📌 Please provide the required settings.\n")

    # base_dir = get_user_input("Enter base directory", os.getcwd())
    # indexing_database = get_user_input("Enter path for the indexing database", os.path.join(base_dir, "file_index.db"))
    # file_changes_database = get_user_input("Enter path for file changes database", os.path.join(base_dir, "file_changes.db"))
    indexing_directories = get_user_input("Enter directories to index (comma-separated)", r"C:\Users\Public\Documents").split(",")
    monitored_directories = get_user_input("Enter monitored directories (comma-separated)", r"D:\,E:\,C:\Users\Public\Downloads").split(",")

    # sensitive_files_dir = get_user_input("Enter directory to store sensitive files", os.path.join(base_dir, "sensitivefiles"))
    # patterns_json_path = get_user_input("Enter path for patterns.json file", os.path.join(base_dir, "patterns.json"))
    # powershell_script_path = get_user_input("Enter path for the PowerShell script", os.path.join(base_dir, "file_protect.ps1"))

    # patterns_to_search = ["email", "password"]  # Default patterns
    # custom_patterns = get_user_input("Enter additional patterns to search (comma-separated)", "")
    # if custom_patterns:
    #     patterns_to_search.extend(custom_patterns.split(","))

    # Generate new settings.py file
# BASE_DIR = r"{base_dir}"
# PATTERNS_JSON_PATH = r"{patterns_json_path}"
# patterns_to_search = {patterns_to_search}
# SENSITIVE_FILES_DIR = r"{sensitive_files_dir}"
# INDEXING_DATABASE = r"{indexing_database}"
# FILE_CHANGES_DATABASE = r"{file_changes_database}"
    settings_content = f'''import os


INDEXING_DIRECTORIES = {indexing_directories}
MONITORED_DIRECTORIES = {monitored_directories}
'''
# POWERSHELL_SCRIPT_PATH = r"{powershell_script_path}"
# patterns_file_path = r"{patterns_json_path}"

    with open("settings.py", "w") as f:
        f.write(settings_content)
    
    print("\n✅ Settings file generated successfully!\n")

if __name__ == "__main__":
    try:
        generate_settings()
        print("🚀 Setup completed. You can now run `master_script.py`.")
    except Exception as e:
        print(f"❌ An error occurred: {e}")
        print("Restarting setup...\n")
        generate_settings()  # Restart if error occurs
