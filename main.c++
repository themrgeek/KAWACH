// main.cpp
#include <iostream>
#include <unordered_map>
#include <vector>
#include <string>
#include <queue>
#include <algorithm>

using namespace std;

// -------- TRIE FOR MALWARE SCANNING --------
struct TrieNode {
    bool isEnd;
    unordered_map<char, TrieNode*> children;

    TrieNode() : isEnd(false) {}
};

class Trie {
    TrieNode* root;
public:
    Trie() { root = new TrieNode(); }

    void insert(string word) {
        TrieNode* node = root;
        for (char ch : word) {
            if (!node->children[ch]) node->children[ch] = new TrieNode();
            node = node->children[ch];
        }
        node->isEnd = true;
    }

    bool search(string text) {
        TrieNode* node = root;
        for (char ch : text) {
            if (!node->children[ch]) return false;
            node = node->children[ch];
        }
        return node->isEnd;
    }
};

// -------- SLIDING WINDOW FOR ANOMALY DETECTION --------
bool detectAnomaly(vector<int>& sysCalls, int k, int threshold) {
    unordered_map<int, int> freq;
    int anomalyCount = 0;

    for (int i = 0; i < sysCalls.size(); ++i) {
        freq[sysCalls[i]]++;
        if (i >= k) freq[sysCalls[i - k]]--;

        if (i >= k - 1) {
            int highFreq = 0;
            for (auto& f : freq)
                if (f.second > 1) highFreq++;
            if (highFreq >= threshold) return true;
        }
    }
    return false;
}

// -------- INTERVAL TREE (Simplified) FOR PORT RULES --------
struct Interval {
    int low, high;
    Interval(int l, int h) : low(l), high(h) {}
};

bool isPortAllowed(vector<Interval>& rules, int port) {
    for (auto rule : rules)
        if (port >= rule.low && port <= rule.high) return true;
    return false;
}

// -------- CLI MENU --------
void menu() {
    Trie trie;
    trie.insert("malware123");
    trie.insert("virus.exe");

    vector<Interval> firewallRules = { {20, 22}, {80, 80}, {443, 443} };

    int choice;
    while (true) {
        cout << "\n===== KAWACH CLI =====\n";
        cout << "1. Scan File Signature\n";
        cout << "2. Detect Anomalous Behavior\n";
        cout << "3. Check Port Access\n";
        cout << "4. Exit\n";
        cout << "Enter choice: ";
        cin >> choice;

        if (choice == 1) {
            string signature;
            cout << "Enter signature to scan: ";
            cin >> signature;
            if (trie.search(signature))
                cout << "⚠️ Malware Detected!\n";
            else
                cout << "✅ File Safe.\n";

        } else if (choice == 2) {
            vector<int> sysCalls = {1, 2, 3, 2, 1, 4, 5, 1}; // Example syscall log
            int k = 3, threshold = 2;
            bool anomaly = detectAnomaly(sysCalls, k, threshold);
            if (anomaly)
                cout << "⚠️ Anomaly Detected in System Calls!\n";
            else
                cout << "✅ System Calls Normal.\n";

        } else if (choice == 3) {
            int port;
            cout << "Enter port number to check: ";
            cin >> port;
            if (isPortAllowed(firewallRules, port))
                cout << "✅ Port Access Allowed.\n";
            else
                cout << "❌ Port Blocked by Firewall.\n";

        } else if (choice == 4) {
            cout << "Exiting KAWACH...\n";
            break;
        } else {
            cout << "Invalid choice.\n";
        }
    }
}

int main() {
    menu();
    return 0;
}
