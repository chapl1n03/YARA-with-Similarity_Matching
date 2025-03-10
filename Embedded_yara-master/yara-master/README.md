# Embedded YARA with Similarity Matching and Fuzzy Logic for Malware detection

This project enhances the existing YARA engine by integrating partial matching functionality alongside its traditional exact matching capabilities. The tool employs fuzzy logic to classify the detection results, enabling a more comprehensive analysis of potential threats.

By adding partial matching, the tool significantly improves malware detection rates, especially in scenarios where exact matches fail. Notably, this tool is highly effective when specific YARA rules for a malware are unavailable. It can detect malware by leveraging the similarity to existing YARA rules designed for related or similar malware. This capability makes the tool a powerful solution for identifying unknown or evolving threats, expanding the scope of malware detection and strengthening cybersecurity defenses.

## Prerequisites

Before building and using this tool, ensure that the following dependencies are installed on your system:

- libyara-dev
- autoconf
- autoconf-archive
- automake
- libtool
- pkg-config
- flex
- bison
- libssl-dev

## Build Instructions

Follow these steps to clone the repository, build the project, and use the tool:

### 1. Clone the Repository
```bash
git clone https://github.com/chapl1n03/YARA-with-Similarity_Matching.git
cd YARA-with-Similarity_Matching/Embedded_yara-master/yara-master
```

### 2. Run the Bootstrap Script
This script prepares the build environment by generating the necessary configuration files.
```bash
./bootstrap.sh
```

### 3. Configure the Build System
Run the `configure` script to set up the build environment for your system.
```bash
./configure
```

### 4. Build the Project
Compile the source code using `make`.
```bash
make
```

### 5. Run the Tool
After building, you can run the tool using:
```bash
./yara
```

## Usage

```bash
./yara [yara-rules_file_name.yar] [target_file_name]
```

## Contact

If you have any questions or issues, feel free to reach out at revan31.n@gmail.com

