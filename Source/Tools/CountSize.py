import os

def get_cs_files_size(directory):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            if filename.endswith('.cs'):
                file_path = os.path.join(dirpath, filename)
                total_size += os.path.getsize(file_path)
    # Convert bytes to kilobytes
    total_size_kb = total_size / 1024
    return total_size_kb

if __name__ == "__main__":
    directory = input("Enter the directory path: ")
    total_size_kb = get_cs_files_size(directory)
    print(f"Total size of all .cs files in '{directory}' and its subdirectories is {total_size_kb:.2f} kB.")
