# Embedded YARA with Similarity Matching and Fuzzy Logic for Malware detection

A brief description of your project/tool goes here.

## Prerequisites

Before building and using this tool, ensure that the following dependencies are installed on your system:

- libyara-dev
- utoconf
- automake
- libtool
- pkg-config
- flex
- bison
- libssl-devsudo

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
Provide instructions on how to use your tool here. Include examples or command-line options if applicable:

```bash
./yara [yara-rules_file_name.yar] [target_file_name]
```

## Contact

If you have any questions or issues, feel free to reach out at revan31.n@gmail.com

