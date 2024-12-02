# Fuzzy Matching Library in C

## Description  
This library performs string similarity calculations using the Levenshtein distance algorithm and related string matching operations. It is developed to integrate fuzzy matching capabilities with YARA rule-based malware detection systems. This library is implemented in C, it provides functions to compute partial ratio similarity for string comparisons.

## Library  
Ensure that all `.c` files are linked together to create a static/dynamic library.  
- [levenshtein.c](./levenshtein.c)  
- [string_processing.c](./string_processing.c)  
- [StringMatcher.c](./StringMatcher.c)
- [utils.c](./utils.c)
- [fuzz.c](./fuzz.c)
- [process.c](./process.c)  

## Usage  
**Note:** Before using the functions, include all the necessary header files in your `main.c` file.  

This library is still under development. Below are examples of the functions currently implemented.  

### Ratio Function  
```c
int similarity_ratio = ratio("Hello folks", "Hello folks!"); 
printf("Similarity ratio is: %d\n", similarity_ratio);
>> Output: Similarity ratio is: 96
```

### Partial Ratio Function
Generally, Partial Ratio function is to measure similarity between two strings by comparing substrings of the longer string against the shorter one.

**Objective:** Enhance YARA-based malware detection by enabling fuzzy matching. 

(This increases the effectiveness of YARA in detecting malware, even when the number of rules is limited.)

According to objective, this Partial Ratio function checks whether string1 (YARA rule) is a substring or variation within string2 (target file content). If so, the similarity score reflects how closely the match aligns, even if the match is not exact.

#### Syntax: 
```c
partial_ratio("string1", "string2");
// String1 -> Yara Rule String
// String2 -> Traget File content
```

#### Test Cases with respective to Yara rule string and Malaware content
```c
partial_ratio("malicious_payload", "This malware contains malicious_payload code.");
>> Output: 100

partial_ratio("encrypted_section", "The malware has an section_method.");
>> Output: 58

partial_ratio("cmd_exec", "Command exec call: cmd-exec was detected.");
>> Output: 87

partial_ratio("file write", "file_write operation detected in logs.");
>> Output: 100

partial_ratio("socket_connect", "Detected obfuscated call: socket_123_connect_456.");
>> Output: 100

partial_ratio("keylogger", "Found function keylogger_captureInput within the code.");
>> Output: 100

partial_ratio("networkScan", "NetworkscanUtility initialized in the sample.");
>> Output: 81

partial_ratio("rootkit_detect", "Alert: rootkit-detection method is active.");
>> Output: 92
```
