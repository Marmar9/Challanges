#include <condition_variable>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <openssl/evp.h>
#include <ostream>
#include <sqlite3.h>
#include <string>
#include <thread>
#include <vector>
std::mutex file_write;

std::string openssl_hash(const std::string &str, const std::string &hash_func) {
  const EVP_MD *md = EVP_get_digestbyname(hash_func.c_str());
  if (md == nullptr) {
    std::cerr << "Unknown hash function: " << hash_func << std::endl;
    return "";
  }

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == nullptr) {
    std::cerr << "Error creating EVP_MD_CTX\n";
    return "";
  }

  if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
    std::cerr << "Error initializing hash context\n";
    EVP_MD_CTX_free(mdctx);
    return "";
  }

  if (EVP_DigestUpdate(mdctx, str.c_str(), str.size()) != 1) {
    std::cerr << "Error updating hash context\n";
    EVP_MD_CTX_free(mdctx);
    return "";
  }

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len = 0;
  if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
    std::cerr << "Error finalizing hash computation\n";
    EVP_MD_CTX_free(mdctx);
    return "";
  }

  char hex[hash_len * 2 + 1];
  for (unsigned int i = 0; i < hash_len; ++i) {
    sprintf(hex + (i * 2), "%02x", hash[i]);
  }
  hex[hash_len * 2] = '\0';

  EVP_MD_CTX_free(mdctx);

  return std::string(hex);
}

std::vector<std::string> supportedAlgorithms = {
    "MD5",        "SHA1",       "MD5-SHA1", "RIPEMD160",  "SHA256",
    "SHA384",     "SHA512",     "SHA224",   "BLAKE2b512", "BLAKE2s256",
    "SHA512-224", "SHA512-256", "SHA3-224", "SHA3-256",   "SHA3-384",
    "SHA3-512",   "SHAKE128",   "SHAKE256", "SHA3-224",   "SHA3-256",
    "SHA3-384",   "SHA3-512",   "SM3",      "SHA512-224", "SHA512-256"};

void worker_function(char **row_data, int num_columns) {

  std::string *hashed_password = new std::string(row_data[3]);

  std::ifstream rockyou("./rockyou.txt");

  std::string hashed_value;
  std::string line;
  std::string used_alg;

  for (const auto &algorithm : supportedAlgorithms) {
    rockyou.clear();
    rockyou.seekg(0, std::ios::beg);

    while (std::getline(rockyou, line)) {
      hashed_value = openssl_hash(line, algorithm);
      if (hashed_value == *hashed_password) {
        used_alg = algorithm;
        goto end_loop;
      }
    }
  }

  std::cout << "password not found for:  " << row_data[1] << std::endl;
  return;
end_loop:
  std::cout << "encrypted: " << line << " for: " << row_data[1] << std::endl;
  std::ofstream result("result.txt", std::ios_base::app);

  std::unique_lock<std::mutex> lock(file_write);

  if (result.is_open()) {
    result << "for - " << row_data[1] << "password =='" << line << "'"
           << " used_alg=" << used_alg << std::endl;
  }
  result.close();
  rockyou.close();
}

int row_count = 0;
int threads_finished = 0;
std::mutex mtx;
std::condition_variable cv;

int callback(void *data, int argc, char **argv, char **azColName) {
  row_count++;

  static int counter = 0;
  if (!counter) {
    std::cout << argc << " Cols" << std::endl;
    counter++;
  }

  char **argv_copy = new char *[argc];
  for (int i = 0; i < argc; i++) {
    argv_copy[i] = new char[strlen(argv[i]) + 1];
    strcpy(argv_copy[i], argv[i]);
  }

  std::thread([argv_copy, argc]() {
    worker_function(argv_copy, argc);
    {
      std::lock_guard<std::mutex> lock(mtx);
      threads_finished++;
    }
    cv.notify_one();

    for (int i = 0; i < argc; i++) {
      delete[] argv_copy[i];
    }
    delete[] argv_copy;
  }).detach();

  // std::cout << "|";
  // for (int i = 0; i < argc; i++) {
  //   std::cout << " " << argv[i] << " |";
  // }
  // std::cout << std::endl;
  return 0;
}

int main() {

  sqlite3 *db;
  int rc;
  char *zErrMsg = nullptr;
  rc = sqlite3_open("./users-challenge.db", &db);

  if (rc) {
    std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
    return (0);
  } else {
    std::cout << "Opened db successfully" << std::endl;
  }
  const char *sql = "SELECT * from users";

  rc = sqlite3_exec(db, sql, callback, nullptr, &zErrMsg);
  if (rc != SQLITE_OK) {
    std::cerr << "SQL error" << zErrMsg << std::endl;
    sqlite3_free(zErrMsg);
  }

  {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock, [] { return threads_finished == row_count; });
  }

  sqlite3_close(db);

  //  OpenSSL_add_all_digests();

  //  std::cout << "Supported hash algorithms:" << std::endl;
  //  for (int nid = 0; nid < 100000; nid++) {
  //    const EVP_MD *md = EVP_get_digestbynid(nid);
  //    if (md != nullptr) {
  //      std::cout << EVP_MD_name(md) << std::endl;
  //    }
  //  }

  //  EVP_cleanup();

  return 0;
}
