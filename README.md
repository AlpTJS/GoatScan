# GoatScan
GoatScan is a cutting-edge CLI tool currently built for Debian-based Linux distributions, to bolster the security of WordPress plugins. Developed using the Argparse module in Python3, GoatScan stands out with its user-friendly interface, making it accessible to both seasoned professionals and novices alike.
This powerful tool focuses on OWASP top ten vulnerabilities, exclusively XSS, SQLi, authentication failures, and command injection vulnerabilities, within the WordPress plugin source code. GoatScan employs a comprehensive approach, combining both static and dynamic scanning techniques. The static analysis, performed using Semgrep, delves deep into the WordPress plugins' source code to identify potential security flaws. In parallel, GoatScan leverages dynamic scanning, harnessing the capabilities of Dalfox, and SQLmap, to thoroughly scrutinise websites utilising the scanned WordPress plugins.
Notably, GoatScan also has the ability to scan authenticated pages, providing a comprehensive dynamic scan that goes beyond surface-level vulnerabilities. Upon completing the scan, GoatScan generates a meticulously structured output file in .txt format. This report includes crucial information, such as the:
  1. Detected vulnerability type
  2. The file path of the file with the vulnerability along with the line number(s) of the vulnerable code
  3. The source and sink of the vulnerable code


## Requirements
### Hardware requirements
Desktop/Laptop with recommended specification of:
CPU with 4 cores, 8 threads
16 GB ram
20 GB disk space
High-definition graphics card 

### Software Requirements
Python - Version 3.11.4

Wget2 - Version 2.1.0

Gf-Patterns - Version 1.9

Semgrep - Version 1.34.0

Kali Linux -  Version Kali 2023.2a

go - Version 1.17

Dalfox - Version 2.9.0

Steps for Automated Installation of Software Requirements are listed below

## Installation GoatScan
1. Download the latest release
2. Extract the files to your local host document root
3. Make sure your web server has file permissions
4. Make sure your installation is protected from unauthorized access
5. You can start using our tool and find vulnerabilities

##  Automated Installation of Software Requirements
1. cd into the 'GoatScan/GoatScan-FYP-Team-12/InstallPackages' directory
2. type 'python InstallPackages.py' to start the installation

## Usage
- Open the command prompt and ensure that you have set up the go environment by entering the following 3 commands:
    1. export PATH=$PATH:/usr/local/go/bin
    2. export GOPATH=$HOME/go
    3. export PATH=$PATH:$GOPATH/bin
- cd into the 'GoatScan/GoatScan-FYP-Team-12/' directory
- type "python GoatScan.py -h" to run GOATSCAN
- Customize scan options using command-line arguments.

## Test Cases
1. Scanning Plugin located in Desktop folder, output to Desktop Folder, scanning a specific authenticated webpage by providing cookie:
`python GoatScan.py Scanning -f ~/Desktop/jibu-pro -o ~/Desktop/ -u "http://localhost/wordpress/wp-admin/admin-ajax.php?action=efbl_generate_popup_html&rand_id=" -c 'wordpress_bbfa5b726c6b7a9cf3cda9370be3ee91=admin%7C1692760286%7CuPNdKBnHWVUHxZrJE7BUpbuX11PTIFUQspOKkwPxUbJ%7Ce4201f33ebf517f7cffa4d323fbad0b5a1ae6c90da6e29839c219e770c415611; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_bbfa5b726c6b7a9cf3cda9370be3ee91=admin%7C1692760286%7CuPNdKBnHWVUHxZrJE7BUpbuX11PTIFUQspOKkwPxUbJ%7C70441bd4575ad89953f8ae3ef7df19fae87ecf2f9b9dfae5764698b2fd74585e;'`

2. Scanning a specific authenticated webpage by providing the WordPress domain name, username and password
`python GoatScan.py Scanning -f ~/Desktop/jibu-pro -o ~/Desktop/ -u "http://localhost/wordpress/wp-admin/admin-ajax.php?action=efbl_generate_popup_html&rand_id="  -d "http://localhost/wordpress" - n admin - p 1qwer\$\#\@\!`

3. Scanning an entire website by providing the website's Domain name (This process is time-consuming for wordpress websites)
`python GoatScan.py Scanning -f ~/Desktop/jibu-pro -o ~/Desktop/ -d 'http://testphp.vulnweb.com/'`


Development
## Development
GOATSCAN is an ongoing project that has been developed as a part of my final year project. As the project evolves, here are some areas of development and future enhancements we plan to explore:

- **Enhanced Vulnerability Detection:** Continuously improving our custom rules and static analysis techniques to detect a broader range of WordPress plugin vulnerabilities.
- **User Interface Enhancement:** Developing a user-friendly web-based dashboard for easier scan initiation, result visualization and report generation.
- **Integration with Security Databases:** Incorporating feeds from prominent security databases to expand the coverage of detected vulnerabilities.
- **Reporting and Remediation:** Generating detailed vulnerability reports with recommended remediation steps to aid developers in addressing identified issues.
- **Community Contributions:** Welcoming contributions from the open-source community to further improve the tool's effectiveness and feature set.

Your feedback and suggestions are highly valuable in shaping the future of GOATSCAN. Please feel free to share your ideas or contribute to the project by opening issues or pull requests.

Stay tuned for updates and exciting new features as we continue to enhance GOATSCAN's capabilities and help you safeguard your WordPress websites.

## Contributing
We welcome contributions from the community! If you find a bug or want to add a new feature, please open an issue or submit a pull request.
