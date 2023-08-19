#!/usr/bin/env python3

import os
import subprocess
import sys


# Install required dependencies
def install_dependencies():

    packages = ['pyfiglet', 'halo', 'inquirer', 'colored','semgrep']
    other_tools = ['go','gf','wget','dalfox','sqlmap']
    print("Installing required dependencies...")

    for package in packages:
        if is_package_installed(package):
            install_package(package)

    for tool in other_tools:
        if is_tool_installed(tool):
            install_tool(tool)


# Check if a package is installed
def is_package_installed(package_name):
    try:
        subprocess.check_output([sys.executable, '-m', 'pip', 'freeze', '--disable-pip-version-check'],
                                universal_newlines=True, stderr=subprocess.DEVNULL).index(package_name)
        return False
    
    except (subprocess.CalledProcessError, ValueError):
        return True

# Install a package using pip
def install_package(package_name):
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package_name],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"Successfully installed {package_name}")
    except subprocess.CalledProcessError:
        print(f"Failed to install {package_name}")


# Check if a tool is installed
def is_tool_installed(tool_name):
    try:
        subprocess.check_output(['which', tool_name], universal_newlines=True)
        return False
    
    except subprocess.CalledProcessError:
        return True


# Install a tool using package manager
def install_tool(tool_name):
    try:

        if(tool_name =='gf'):
            # Define the path to the shell script
            shell_script_path = 'Install_gf.sh' 
            # Set the execute permission on the shell script file
            os.chmod(shell_script_path, 0o755)
            # Execute the shell script
            subprocess.run(['bash', shell_script_path], check=True)

        elif(tool_name =='dalfox'):
            # Define the path to the shell script
            shell_script_path = 'Install_dalfox.sh'
            # Set the execute permission on the shell script file
            os.chmod(shell_script_path, 0o755)
            # Execute the shell script
            subprocess.run(['bash', shell_script_path], check=True)
            
        else:
            if (tool_name == 'go'):
                tool_name ='golang'
                
            subprocess.check_call(['sudo','apt', 'update'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.check_call(['sudo','apt', 'install', '-y', tool_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print(f"Successfully installed {tool_name}")

    except subprocess.CalledProcessError:
        print(f"Failed to install {tool_name}")


#Start running workingon.py 
if (__name__ == '__main__'): 
    # Check and install dependencies
    install_dependencies()
