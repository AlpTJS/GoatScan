import subprocess
import re

def run_gf(url_file, vulnerability_type):
    # Run gf for the specified vulnerability type
    gf_command = ['gf', vulnerability_type, url_file]
    process = subprocess.Popen(gf_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # stdout & stderr are vars that store gf's output IN BYTES
    stdout, stderr = process.communicate()

    # Decode bytes to string
    stdout = stdout.decode()

    # Clean the output using shell command: cat ~/urls.txt | gf sqli | sed 's/temp\///' | sort -u | tee sqli-output.txt
    sed_command = f"sed 's/temp\\///' | sort -u"
    cleaned_output = subprocess.check_output(f"cat {url_file} | gf {vulnerability_type} | {sed_command}", shell=True, text=True).splitlines()

    # Print result directly to the user
    print("Cleaned gf output:")
    print('\n'.join(cleaned_output))

    # Write cleaned output to a text file
    output_file = f'{vulnerability_type}-output.txt'
    with open(output_file, 'w') as f:
        f.write('\n'.join(cleaned_output))
