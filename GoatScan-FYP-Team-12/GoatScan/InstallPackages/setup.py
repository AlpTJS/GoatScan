from setuptools import setup, find_packages

with open("README.md", "r") as f:
    user_guide = f.read()


setup(
    name='GoatScan',
    version='1.0.0',
    author='Alphonsus Teo, Haw Zong Han, Tan Ying Song, Md Naufal, Aqmar Haziq, Andy Kurniawan',
    author_email='zonghan3251@gmail.com',
    description='A vulnerability scanner that scans WP plugins',
    packages=find_packages(),  # auto-detect if have init
    long_description=user_guide,
    long_description_content_type="text/markdown",
    install_requires=[
        'semgrep',
        # Other dependencies
    ],
    
    package_data={
        'scanner': ['semgrep_rules/*.yaml'],
    },  # specify  all .yaml files within the semgrep-rule folder to be included in the scanner package


)
