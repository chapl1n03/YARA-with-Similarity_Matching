#include <stdio.h>
#include <stdlib.h>
#include "fuzz.h"
#include "utils.h"
#include "process.h"
#include "string_processing.h"
#include "StringMatcher.h"
#include "levenshtein.h"

void run_tests() {
    // Test cases where str1 (YARA rule) is checked against str2 (malware file content)
    const char *test_cases[][2] = {
        // Case 1: Exact match of YARA rule in malware content
        {"malicious_payload", "This malware contains malicious_payload code."},
        
        // Case 3: YARA rule matches as part of a larger function name
        {"encrypted_section", "The malware has an section_method."},
        
        // Case 5: YARA rule matches despite special character differences
        {"cmd_exec", "Command exec call: cmd-exec was detected."},
        
        // Case 6: YARA rule with spaces, file content with underscores
        {"file write", "file_write operation detected in logs."},
        
        // Case 7: YARA rule matches as part of an obfuscated sequence
        {"socket_connect", "Detected obfuscated call: socket_123_connect_456."},
        
        // Case 8: YARA rule is a subset of a larger variable name
        {"keylogger", "Found function keylogger_captureInput within the code."},
        
        // Case 9: YARA rule matches with added prefix and suffix
        {"networkScan", "NetworkscanUtility initialized in the sample."},
        
        // Case 10: YARA rule matches when certain characters are replaced
        {"rootkit_detect", "Alert: rootkit-detection method is active."}
    };

    int total_cases = sizeof(test_cases) / sizeof(test_cases[0]);
    for (int i = 0; i < total_cases; ++i) {
        const char *str1 = test_cases[i][0];
        const char *str2 = test_cases[i][1];
        int score = partial_ratio(str1, str2); // Call your partial_ratio function
        
        printf("Test %d:\n", i + 1);
        printf("YARA Rule: \"%s\"\n", str1);
        printf("Malware Content: \"%s\"\n", str2);
        printf("Partial Ratio: %d\n\n", score);
    }
}

int main() {
    printf("Running partial_ratio tests:\n\n");
    run_tests();
    return 0;
}

/*
// Function to run all test cases
void run_tests() {
    // Test cases where str1 (YARA rule) is checked against str2 (malware file content)
    const char *test_cases[][2] = {
        // Case 1: YARA rule matches exactly a portion of the malware file
        {"malicious payload", "This malware contains malicious_payload code."},
        
        // Case 2: YARA rule matches with additional characters before and after in the file
        {"trojan function", "This is a function trojan used in malware development."},
        
        // Case 3: YARA rule matches but with different casing
        {"virusCode", "The viruscode is embedded within the file system."},
        
        // Case 4: YARA rule partially matches a larger function name
        {"encrypted_section", "The malware has an section for obfuscation."},
        
        // Case 5: YARA rule matching a pattern with numeric values
        {"pattern_1234", "Detected pattern_1234xyz embedded in the executable."},
        
        // Case 6: YARA rule is a substring in a longer sequence of code
        {"keylogger", "function_keylogger_captureInput() is found in the codebase."},
        
        // Case 7: YARA rule with underscores, file content with spaces
        {"command_injection", "Potential command injection found in logs."},
        
        // Case 8: YARA rule with special characters, file content includes variations
        {"$shell_code$", "Shell code detected as $shell_code$ payload."},
        
        // Case 9: YARA rule as part of a function name in file content
        {"data_exfiltration", "Warning: data_exfiltrationRoutine detected in binary."},
        
        // Case 10: YARA rule includes numeric values and matches similar patterns
        {"exploit_2022", "Security alert: exploit_2022 method triggered."},
        
        // Case 11: Rule matches but file has slight variations
        {"malware_scan", "Performing malware scan. MalwareScanUtil is invoked."},
        
        // Case 12: Malware content contains the YARA rule with additional encoding
        {"base64_decode", "base64_decode utility is embedded with extra encryption layers."},
        
        // Case 13: YARA rule and malware content have different separators
        {"session_hijack", "A method for session-hijack was found in the malware."},
        
        // Case 14: Matching with different spelling or abbreviation
        {"ransomware_detect", "RansomWareDetectSystem flagged this file."},
        
        // Case 15: YARA rule matches part of a longer, chained method call
        {"dll_injection", "malicious.dll_injection_method is called during execution."},
        
        // Case 16: YARA rule only matches the beginning of the malware content
        {"startup_check", "startup_checkProcess for autostart was located."},
        
        // Case 17: Malware content repeats a similar pattern multiple times
        {"heap_overflow", "heap_overflow, heap_overflows, and overflow routines detected."},
        
        // Case 18: YARA rule matches a substring within a variable
        {"file_encrypt", "FileEncryptMechanism used by the malware."},
        
        // Case 19: YARA rule detects an obfuscated pattern in file content
        {"exec_virus", "Obfuscated exec_virus code block discovered."},
        
        // Case 20: YARA rule is present within a sequence with noise
        {"socket_connect", "socket123_connect789 routine found in malware trace."},
        
        // Case 21: Partial match due to prefix or suffix differences
        {"user_authentication", "user_authenticationProcess observed in file."},
        
        // Case 22: Pattern matches even with a case mismatch and additional characters
        {"networkScan", "NetworkscanUtility initiated for reconnaissance."},
        
        // Case 23: Special character and symbol differences between YARA rule and file content
        {"dropper*payload", "Detected dropper_payload utility with * symbols."},
        
        // Case 24: Matching the YARA rule in an obfuscated sequence
        {"file_write", "Obfuscation routine uses file_writeXYZ() method."},
        
        // Case 25: Matching an encrypted or hidden version of YARA rule
        {"exec_cmd", "Encrypted call exec_cmd@ detected."},
        
        // Case 26: Malware file content partially rearranges the rule
        {"memory_access", "Routine memory-access_control found in the sample."},
        
        // Case 27: YARA rule contains underscores, and file has hyphens
        {"privilege_escalation", "Privilege-Escalation code segment identified."},
        
        // Case 28: Exact substring match amidst unrelated text
        {"ddos_attack", "Network log: ddos_attack detected."},
        
        // Case 29: Rule matches when spaces are removed
        {"crypto_miner", "The cryptominer utility was found."},
        
        // Case 30: Rule matches when certain characters are replaced
        {"rootkit_detection", "A rootkit-detection method was observed."}
    };

    int total_cases = sizeof(test_cases) / sizeof(test_cases[0]);
    for (int i = 0; i < total_cases; ++i) {
        const char *str1 = test_cases[i][0];
        const char *str2 = test_cases[i][1];
        int score = partial_ratio(str1, str2); // Call your partial_ratio function
        
        printf("Test %d:\n", i + 1);
        printf("YARA Rule: \"%s\"\n", str1);
        printf("Malware Content: \"%s\"\n", str2);
        printf("Partial Ratio: %d\n\n", score);
    }
}

int main() {
    printf("Running partial_ratio tests:\n\n");
    run_tests();
    return 0;
}*/

/*
void run_tests() {
    const char *test_cases[][2] = {
        {"hello world", "hello"},                 // Substring match
        {"abcdef", "cde"},                        // Substring in the middle
        {"fuzzy matching algorithm", "fuzzy"},    // Partial match at the start
        {"fuzzy matching algorithm", "algorithm"}, // Partial match at the end
        {"abcdxyz", "xyzabc"},                    // Partial match with different order
        {"abcdefgh", "abcd"},                     // Exact substring match
        {"abcdefgh", "wxyz"},                     // No common substring
        {"case insensitive", "CASE INSENSITIVE"}, // Case sensitivity check
        {"", "non-empty"},                        // One string empty
        {"non-empty", ""},                        // Other string empty
        {"", ""},                                 // Both strings empty
        {"repeat repeat repeat", "repeat"},       // Repeated substring
        {"a quick brown fox", "quick brown fox"}, // Partial match in the middle
        {"spaces and symbols!?", "and symbols"},  // Special characters and spaces
        {"12345abcde", "abcde12345"},             // Numeric and alphabetic mix
        {"partial test case", "test case"},       // Partial match after a word
        {"short", "very long non-matching string"} // Short vs long non-matching
    };

    int total_cases = 17;
    for (int i = 0; i < total_cases; ++i) {
        const char *str1 = test_cases[i][0];
        const char *str2 = test_cases[i][1];
        int score = partial_ratio(str1, str2);
        
        printf("Test %d:\n", i + 1);
        printf("String 1: \"%s\"\n", str1);
        printf("String 2: \"%s\"\n", str2);
        printf("Partial Ratio: %d\n\n", score);
    }
}

int main() {
    printf("Running partial_ratio tests:\n\n");
    run_tests();
    return 0;
}
*/
/*
// Test cases for the partial_ratio function
void run_tests() {
    const char *test_cases[][2] = {
        {"hello world", "hello"},
        {"abcdef", "cde"},
        {"ABCDE", "abcde"},
        {"fuzzy matching", "fuzzy"},
        {"abcdxyz", "xyzabc"},
        {"abcdefgh", "abcd"},
        {"abcdefgh", "wxyz"},
        {"case-sensitive", "Case-Sensitive"},
        {"", "non-empty"},
        {"non-empty", ""},
        {"", ""},
        {"repeat repeat repeat", "repeat"},
        {"  a quick brown fox", "quick brown fox"},
        {"spaces and symbols!?", "and symbols"},
        {"12345abcde", "abcde12345"},
        {"special@#$", "@#$"},
        {"white   space", "white space"},
        {"trailing space ", "trailing space"},
        {"leading space", " leading space"},
        {"different cases", "Different Cases"},
        {"same", "same"},
        {"partial overlap", "overlap partial"},
        {"numbers12345", "12345numbers"},
        {"abcdefg", "efgabc"},
        {"longer example text", "example"},
        {"unicode✓test", "test✓unicode"},
        {"abcdefgh", "abcdefghijk"},
        {"common sequence", "sequence"},
        {"similar characters", "characters similar"},
        {"123456", "654321"},
        {"AbCdEfG", "abcdefg"},
        {"repeat repeat", "repeat"},
        {"punctuation, test!", "test punctuation,"},
        {"A long string of text", "long string"},
        {"non-cyclic example", "example non-cyclic"},
        {"stringwithnumbers123", "123456789stringwithnumbers"},
        {"case Sensitive Match", "sensitive case match"},
        {"singleword", "single"},
        {"mixed CASE and cases", "cases and CASE mixed"},
        {"substring test", "test substring"},
        {"Fyp", "fyp"},
        {"Fyp project", "fyp project"},
        {"Text to search with space", "read the mean ing of text in between lines. Words are few. To search for a long lost son. Beneath a starry sky in the space between the world's."}
    };

    int total_cases = sizeof(test_cases) / sizeof(test_cases[0]);
    for (int i = 0; i < total_cases; ++i) {
        const char *str1 = test_cases[i][0];
        const char *str2 = test_cases[i][1];
        int score = partial_ratio(str1, str2); // Call your partial_ratio function
        
        printf("Test %d:\n", i + 1);
        printf("String 1: \"%s\"\n", str1);
        printf("String 2: \"%s\"\n", str2);
        printf("Partial Ratio: %d\n\n", score);
    }
}

int main() {
    printf("Running partial_ratio tests:\n\n");
    run_tests();
    return 0;
}*/
