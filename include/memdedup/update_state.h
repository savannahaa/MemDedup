#pragma once
#include "dedup_protocol.h"
#include <map>
#include <set>
#include <string>
#include <optional>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <limits>
namespace memdedup {
struct Request {
    int provider;
    std::vector<std::string> ids;
    double arrival, deadline;
};
struct Batch {
    uint64_t id;
    std::vector<int> roster;
    std::vector<std::string> requests;
};
class Scheduler {
    std::map<int, Request> pending;
    std::map<uint64_t, std::map<int, Request>> inflight;
    uint64_t next = 1;

  public:
    void submit(int p, std::string id, double arrival, double maxDelay) {
        if (maxDelay < 0)
            throw std::invalid_argument("negative delay");
        auto i = pending.find(p);
        if (i == pending.end())
            pending.emplace(p, Request{p, {id}, arrival, arrival + maxDelay});
        else {
            if (std::find(i->second.ids.begin(), i->second.ids.end(), id) == i->second.ids.end())
                i->second.ids.push_back(id);
            i->second.arrival = std::min(i->second.arrival, arrival);
            i->second.deadline = std::min(i->second.deadline, arrival + maxDelay);
        }
    }
    double nextDeadline() const {
        double deadline = std::numeric_limits<double>::infinity();
        for (auto &[p, r] : pending)
            deadline = std::min(deadline, r.deadline);
        return deadline;
    }
    std::optional<Batch> trigger(double now, size_t threshold, size_t minimum,
                                 const std::vector<int> &online) {
        if (threshold == 0 || minimum == 0)
            throw std::invalid_argument("participation thresholds must be positive");
        if (pending.empty())
            return {};
        double deadline = 1e100;
        for (auto &[p, r] : pending)
            deadline = std::min(deadline, r.deadline);
        if (pending.size() < threshold && now < deadline)
            return {};
        Batch b{next, {}, {}};
        for (auto &[p, r] : pending) {
            b.roster.push_back(p);
            b.requests.insert(b.requests.end(), r.ids.begin(), r.ids.end());
        }
        for (int p : online)
            if (b.roster.size() < minimum &&
                std::find(b.roster.begin(), b.roster.end(), p) == b.roster.end())
                b.roster.push_back(p);
        if (b.roster.size() < minimum)
            return {};
        inflight.emplace(next++, pending);
        pending.clear();
        return b;
    }
    void acknowledge(uint64_t id, bool success) {
        auto i = inflight.find(id);
        if (i == inflight.end())
            throw std::invalid_argument("unknown batch");
        if (!success)
            for (auto &[p, r] : i->second)
                for (auto &x : r.ids)
                    submit(p, x, r.arrival, r.deadline - r.arrival);
        inflight.erase(i);
    }
};
struct State {
    std::unordered_set<Item> records;
    std::set<uint64_t> batches;
    std::set<std::string> requests;
    bool commit(uint64_t id, const std::vector<std::string> &ids,
                const std::unordered_set<Item> &inserts, const std::unordered_set<Item> &deletes,
                bool complete) {
        if (!complete)
            return false;
        if (batches.count(id))
            return false;
        for (auto &x : ids)
            if (requests.count(x))
                return false;
        auto next = records;
        next.insert(inserts.begin(), inserts.end());
        for (auto &x : deletes)
            next.erase(x);
        records.swap(next);
        batches.insert(id);
        requests.insert(ids.begin(), ids.end());
        return true;
    }
    void save(const std::string &path) const {
        std::ofstream f(path + ".tmp");
        f << "MEMDEDUP_UPDATE_STATE_512_V2\n"
          << batches.size() << ' ' << requests.size() << ' ' << records.size() << '\n';
        for (auto x : batches)
            f << x << '\n';
        for (auto &x : requests)
            f << x << '\n';
        for (auto x : records)
            f << std::hex << x << '\n';
        f.close();
        if (!f)
            throw std::runtime_error("snapshot write failed");
        std::filesystem::rename(path + ".tmp", path);
    }
    static State load(const std::string &path) {
        State s;
        std::ifstream f(path);
        std::string magic;
        size_t a = 0, b = 0, c = 0;
        f >> magic >> a >> b >> c;
        if (!f || magic != "MEMDEDUP_UPDATE_STATE_512_V2")
            throw std::runtime_error("bad snapshot");
        uint64_t id;
        for (size_t i = 0; i < a; ++i) {
            f >> id;
            s.batches.insert(id);
        }
        std::string x;
        for (size_t i = 0; i < b; ++i) {
            f >> x;
            s.requests.insert(x);
        }
        for (size_t i = 0; i < c; ++i) {
            f >> x;
            s.records.emplace("0x" + x);
        }
        if (!f)
            throw std::runtime_error("truncated snapshot");
        return s;
    }
};
inline Item packOperation(Item ciphertext, bool deletion) {
    if (ciphertext >= Field::recordDomainLimit())
        throw std::invalid_argument("ciphertext outside reserved update domain");
    return (ciphertext << 1) + int(deletion);
}
inline std::pair<Item, bool> unpackOperation(Item v) {
    if ((v >> 1) >= Field::recordDomainLimit())
        throw std::invalid_argument("invalid packed operation");
    return {v >> 1, bool(v & 1)};
}
} // namespace memdedup
