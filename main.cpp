#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <regex>
#include <sqlite3.h>
#include <filesystem>
#include <sstream>

struct APIInfo {
    std::string name;
    std::string category;  // "OS" or "Standard"
    std::string signature;
};

class APIAnalyzer {
private:
    sqlite3* db;
    
    // Helper function to check if table is empty
    bool isTableEmpty() {
        const char* sql = "SELECT COUNT(*) FROM api_signatures;";
        sqlite3_stmt* stmt;
        int count = 0;
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                count = sqlite3_column_int(stmt, 0);
            }
        }
        sqlite3_finalize(stmt);
        return count == 0;
    }

    bool initializeDatabase() {
        std::cout << "Initializing database..." << std::endl;
        
        int rc = sqlite3_open("api_signatures.db", &db);
        if (rc) {
            std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
            return false;
        }

        // Create table
        const char* sql = 
            "CREATE TABLE IF NOT EXISTS api_signatures("
            "name TEXT NOT NULL,"
            "category TEXT NOT NULL,"
            "signature TEXT NOT NULL);";

        char* errMsg = 0;
        rc = sqlite3_exec(db, sql, 0, 0, &errMsg);
        if (rc != SQLITE_OK) {
            std::cerr << "SQL error: " << errMsg << std::endl;
            sqlite3_free(errMsg);
            return false;
        }

        // Only populate if table is empty
        if (isTableEmpty()) {
            std::cout << "Database is empty, populating with known APIs..." << std::endl;
            populateKnownAPIs();
        } else {
            std::cout << "Database already populated." << std::endl;
        }
        return true;
    }

    void populateKnownAPIs() {
        // Windows APIs
        addAPISignature("CreateFile", "OS", "HANDLE (LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)");
        addAPISignature("WriteFile", "OS", "BOOL (HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)");
        addAPISignature("ReadFile", "OS", "BOOL (HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)");
        addAPISignature("CloseHandle", "OS", "BOOL (HANDLE)");
        
        // POSIX (Unix/Linux/MacOS) APIs
        addAPISignature("open", "OS", "int (const char*, int, ...)");
        addAPISignature("write", "OS", "ssize_t (int, const void*, size_t)");
        addAPISignature("read", "OS", "ssize_t (int, void*, size_t)");
        addAPISignature("close", "OS", "int (int)");
        addAPISignature("fork", "OS", "pid_t (void)");
        addAPISignature("exec", "OS", "int (const char*, char* const[])");
        
        // Standard Library
        addAPISignature("fopen", "Standard", "FILE* (const char*, const char*)");
        addAPISignature("fwrite", "Standard", "size_t (const void*, size_t, size_t, FILE*)");
        addAPISignature("fread", "Standard", "size_t (void*, size_t, size_t, FILE*)");
        addAPISignature("fclose", "Standard", "int (FILE*)");
        addAPISignature("printf", "Standard", "int (const char*, ...)");
        addAPISignature("scanf", "Standard", "int (const char*, ...)");
        addAPISignature("malloc", "Standard", "void* (size_t)");
        addAPISignature("free", "Standard", "void (void*)");
        addAPISignature("strlen", "Standard", "size_t (const char*)");
        addAPISignature("strcpy", "Standard", "char* (char*, const char*)");
        
        std::cout << "Database populated successfully!" << std::endl;
    }

    void addAPISignature(const std::string& name, const std::string& category, const std::string& signature) {
        const char* sql = "INSERT INTO api_signatures (name, category, signature) VALUES (?, ?, ?);";
        sqlite3_stmt* stmt;
        
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
        if (rc != SQLITE_OK) {
            std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
            return;
        }

        sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, category.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, signature.c_str(), -1, SQLITE_STATIC);
        
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            std::cerr << "Failed to insert API: " << sqlite3_errmsg(db) << std::endl;
        }
        
        sqlite3_finalize(stmt);
    }

    std::vector<APIInfo> queryAPI(const std::string& name) {
        std::vector<APIInfo> results;
        const char* sql = "SELECT * FROM api_signatures WHERE name = ?;";
        sqlite3_stmt* stmt;
        
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
        if (rc != SQLITE_OK) {
            return results;
        }

        sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_STATIC);
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            APIInfo info;
            info.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            info.category = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            info.signature = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            results.push_back(info);
        }

        sqlite3_finalize(stmt);
        return results;
    }

    std::string extractFunctionSignature(const std::string& line) {
        std::regex functionPattern(R"((\w+)\s*\([^)]*\))");
        std::smatch matches;
        if (std::regex_search(line, matches, functionPattern)) {
            return matches[1];
        }
        return "";
    }

public:
    APIAnalyzer() {
        if (!initializeDatabase()) {
            throw std::runtime_error("Failed to initialize database");
        }
        
        // Verify database has entries
        const char* sql = "SELECT COUNT(*) FROM api_signatures;";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                int count = sqlite3_column_int(stmt, 0);
                std::cout << "Database contains " << count << " API signatures." << std::endl;
            }
        }
        sqlite3_finalize(stmt);
    }

    void analyzeFile(const std::string& filepath) {
        std::cout << "Analyzing file: " << filepath << std::endl;
        
        std::ifstream file(filepath);
        if (!file.is_open()) {
            std::cerr << "Cannot open file: " << filepath << std::endl;
            return;
        }

        std::set<std::string> osAPIs;
        std::set<std::string> stdAPIs;
        std::set<std::string> ambiguousAPIs;

        std::string line;
        int lineNumber = 0;
        while (std::getline(file, line)) {
            lineNumber++;
            std::string signature = extractFunctionSignature(line);
            if (!signature.empty()) {
                std::cout << "Found potential API call at line " << lineNumber << ": " << signature << std::endl;
            }

            if (signature.empty()) continue;

            std::string functionName = signature;
            auto apis = queryAPI(functionName);

            if (apis.empty()) continue;

            if (apis.size() > 1) {
                ambiguousAPIs.insert(functionName);
                std::cout << "Ambiguous API found: " << functionName << std::endl;
                std::cout << "Please inspect manually. Context: " << line << std::endl;
            } else {
                if (apis[0].category == "OS") {
                    osAPIs.insert(functionName);
                    std::cout << "Found OS API: " << functionName << std::endl;
                } else {
                    stdAPIs.insert(functionName);
                    std::cout << "Found Standard API: " << functionName << std::endl;
                }
            }
        }

        // Write results to output file
        std::ofstream output("api_analysis_results.txt");
        output << "OS APIs\tStandard Libraries\n";
        
        auto osIter = osAPIs.begin();
        auto stdIter = stdAPIs.begin();
        
        while (osIter != osAPIs.end() || stdIter != stdAPIs.end()) {
            if (osIter != osAPIs.end()) {
                output << *osIter;
                ++osIter;
            }
            output << "\t";
            if (stdIter != stdAPIs.end()) {
                output << *stdIter;
                ++stdIter;
            }
            output << "\n";
        }

        if (!ambiguousAPIs.empty()) {
            output << "\nAmbiguous APIs requiring manual inspection:\n";
            for (const auto& api : ambiguousAPIs) {
                output << api << "\n";
            }
        }

        std::cout << "\nAnalysis complete! Found:" << std::endl;
        std::cout << "- " << osAPIs.size() << " OS APIs" << std::endl;
        std::cout << "- " << stdAPIs.size() << " Standard Library APIs" << std::endl;
        std::cout << "- " << ambiguousAPIs.size() << " Ambiguous APIs" << std::endl;
    }

    ~APIAnalyzer() {
        sqlite3_close(db);
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <path_to_cpp_file>" << std::endl;
        return 1;
    }

    try {
        APIAnalyzer analyzer;
        analyzer.analyzeFile(argv[1]);
        std::cout << "Results written to api_analysis_results.txt" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
