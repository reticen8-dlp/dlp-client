import time
import indexing
import settings
import subprocess
import sys

# # Ensure settings.py is generated
# if not os.path.exists("settings.py"):
#     print("⚠️ No settings found! Running installer first...")
#     import installer  # Run the installer
#     installer.generate_settings()


db_path = settings.INDEXING_DATABASE
target_directory = settings.INDEXING_DIRECTORIES
patterns_to_search = settings.patterns_to_search


def start_script(script_name):
    """Start a Python script in a separate terminal and keep it running."""
    try:
        subprocess.Popen([sys.executable, script_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Started {script_name} in a separate terminal.")
    except Exception as e:
        print(f"Error starting {script_name}: {e}")

def main():

    #indexing function
    print("Starting indexing process...")
    start_time = time.time()
    indexer = indexing.FileSystemIndexer(db_path)
    # for directory in target_directory:
    #     print(f"Indexing directory: {directory}")
    #     indexer.index_filesystem(directory)
    indexer.index_filesystem(target_directory)
    print(f"\nTotal time taken: {time.time() - start_time:.2f} seconds")


    #store sensitive files
    print("\nFetching sensitive files...")
    import store_sensitivefiles
    target_directories = settings.SENSITIVE_FILES_DIR
    sensitive_files = store_sensitivefiles.fetch_sensitive_files(db_path,patterns_to_search)

    if sensitive_files:
        print(f"Found {len(sensitive_files)} sensitive files. Copying to {target_directories}...")
        store_sensitivefiles.copy_files_to_directory(sensitive_files, target_directories)
    else:
        print("No sensitive files found.")


    #update indexing database
    # Start the update_indexing script in a separate process
    start_script("update_indexing.py")

    #file monitoring
    # Start file_monitoring.py in a separate terminal
    start_script("file_monitoring.py")

    #clipboard monitoring
    # Start clipboard_monitoring.py in a separate terminal
    start_script("clipboard_monitoring.py")  

    #file permissions
    # Start file_permissions.py in a separate terminal
    # import file_permissions
    # file_permissions.main()



if __name__ == "__main__":
    main()
