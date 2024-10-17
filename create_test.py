import csv
import os

# Define input and output paths
input_file = 'nsl-kdd-data/KDDTest+.txt'
output_dir = 'tests'

# Ensure the output directory exists
os.makedirs(output_dir, exist_ok=True)

# Initialize lists to store records
normal_records = []
non_normal_records = []

# Read the input file and categorize records
with open(input_file, 'r') as f:
    csv_reader = csv.reader(f)
    for row in csv_reader:
        if row[-2] == 'normal':
            normal_records.append(row)
        else:
            non_normal_records.append(row)

# Function to write records to a file
def write_records(filename, records):
    with open(os.path.join(output_dir, filename), 'w', newline='') as f:
        csv_writer = csv.writer(f)
        csv_writer.writerows(records)

# Generate test1.txt: first 10 normal records
write_records('test1.txt', normal_records[:10])

# Generate test2.txt: first 10 non-normal records
write_records('test2.txt', non_normal_records[:10])

# Generate test3.txt: first 5 normal and first 5 non-normal records
write_records('test3.txt', normal_records[:5] + non_normal_records[:5])

print("Files generated successfully in the 'tests' directory.")