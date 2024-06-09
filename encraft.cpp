#include <iostream>
#include <vector>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <string>

// SHA-256 hash function
std::string sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Block structure
class Block {
public:
    int index;
    std::string previousHash;
    std::string timestamp;
    std::string data;
    std::string hash;
    int nonce;

    Block(int idx, const std::string& prevHash, const std::string& d)
        : index(idx), previousHash(prevHash), data(d), nonce(0) {
        timestamp = currentTime();
        hash = calculateHash();
    }

    void mineBlock(int difficulty) {
        std::string target(difficulty, '0');
        while (hash.substr(0, difficulty) != target) {
            nonce++;
            hash = calculateHash();
        }
        std::cout << "Block mined: " << hash << std::endl;
    }

private:
    std::string calculateHash() const {
        std::stringstream ss;
        ss << index << previousHash << timestamp << data << nonce;
        return sha256(ss.str());
    }

    std::string currentTime() const {
        std::time_t now = std::time(0);
        std::tm* now_tm = std::localtime(&now);
        std::stringstream ss;
        ss << std::put_time(now_tm, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

// Blockchain structure
class Blockchain {
public:
    Blockchain(int diff) : difficulty(diff) {
        chain.push_back(createGenesisBlock());
    }

    void addBlock(const std::string& data) {
        int index = chain.size();
        std::string previousHash = getLatestBlock().hash;
        Block newBlock(index, previousHash, data);
        newBlock.mineBlock(difficulty);
        chain.push_back(newBlock);
    }

    void printBlockchain() const {
        for (const Block& block : chain) {
            std::cout << "Block #" << block.index << "\n";
            std::cout << "Previous Hash: " << block.previousHash << "\n";
            std::cout << "Timestamp: " << block.timestamp << "\n";
            std::cout << "Data: " << block.data << "\n";
            std::cout << "Hash: " << block.hash << "\n";
            std::cout << "Nonce: " << block.nonce << "\n\n";
        }
    }

private:
    std::vector<Block> chain;
    int difficulty;

    Block createGenesisBlock() {
        return Block(0, "0", "Genesis Block");
    }

    Block getLatestBlock() const {
        return chain.back();
    }
};

// Main function
int main() {
    int difficulty = 4; // Adjust difficulty as needed
    Blockchain emrecraftBlockchain(difficulty);

    emrecraftBlockchain.addBlock("First EmreCraft Block Data");
    emrecraftBlockchain.addBlock("Second EmreCraft Block Data");
    emrecraftBlockchain.addBlock("Third EmreCraft Block Data");

    emrecraftBlockchain.printBlockchain();

    return 0;
}
