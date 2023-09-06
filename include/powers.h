#ifndef POWERS_H
#define POWERS_H
// STD
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <future>
#include <iostream>
#include <memory>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "thread_pool_mgr.h"

using namespace std;

/**
    PowersDag represents a DAG for computing all powers of a given query
   ciphertext in a depth-optimal manner given a certain "base" (sources) of
   powers of the query. For example, the computation up to power 7 with sources
   1, 2, 5 one can represented as the DAG with nodes 1..7 and edges 1 --> 3 <--
   2 (q^3 = q^1 * q^2) 2 --> 4 <-- 2 (q^4 = q^2 * q^2; repeated edge) 1 --> 6
   <-- 5 (q^6 = q^1 * q^5) 2 --> 7 <-- 5 (q^7 = q^2 * q^5) The graph above
   describes how q^1...q^7 can be computed from q^1, q^2, and q^5 with a depth 1
    circuit. A PowersDag is configured from a given set of source powers ({ 1,
   2, 5 } in the example above). The class contains no mechanism for discovering
   a good set of source powers: it is up to the user to find using methods
   external to APSI.
    */
class PowersDag {
public:
  /**
  Represents an individual node in the PowersDag. The node holds the power it
  represents, and depth in the DAG. Source nodes (i.e., powers of a query that
  are given directly and do not need to be computed), have depth zero. The node
  also holds the powers of its parents; parent values both 0 denotes that this
  is a source node. If only one of the parent values is zero this node is
  invalid and the PowersDag is in an invalid state. For the DAG to be in a valid
  state, for each non-source node, the sum of the powers of the parent nodes of
  a given must equal the power of that node.
  */
  struct PowersNode {
    /**
    The power represented by this node. In a valid PowersDag this can never be
    zero.
    */
    std::uint32_t power = 0;

    /**
    The depth of this node in the DAG.
    */
    std::uint32_t depth = 0;

    /**
    Holds the powers of the two parents of this node. Both values must either be
    zero indicating that this is a source node, or non-zero.
    */
    std::pair<std::uint32_t, std::uint32_t> parents{0, 0};

    /**
    Returns whether this is a source node.
    */
    bool is_source() const { return !parents.first && !parents.second; }
  };

  /**
  Creates a new PowersDag. The DAG must be configured before it can be used.
  */
  PowersDag() = default;

  /**
  Attempts to initialize the PowersDag by computing target powers from source
  powers. The function returns true on success.
  */
  bool configure(std::set<std::uint32_t> &source_powers,
                 std::set<std::uint32_t> &target_powers);

  /**
  Reset all internal members of the PowersDag instance.
  */
  void reset() {
    target_powers_.clear();
    depth_ = 0;
    source_count_ = 0;
    configured_ = false;
    total_multiplications = 0;
  }

  /**
  Returns whether the PowersDag was successfully configured.
  */
  bool is_configured() const { return configured_; }

  /**
  Returns the target powers that this PowersDag computes. If the PowersDag is
  not configured, this function throws an exception.
  */
  std::set<std::uint32_t> target_powers() const;

  /**
  Returns the maximal depth of the computation represented by the PowersDag. If
  the PowersDag is not configured, this function throws an exception.
  */
  std::uint32_t depth() const;

  /**
  Returns the number of source nodes required by the PowersDag. If the PowersDag
  is not configured, this function throws an exception.
  */
  std::uint32_t source_count() const;

  /**
  Returns a set of source nodes for this PowersDag. If the PowersDag is not
  configured, this function throws an exception.
  */
  std::vector<PowersNode> source_nodes() const;

  /**
  Returns this PowersDag in the DOT format as a string.
  */
  std::string to_dot() const;

  /**
  Applies a function in a topological order to each node in the PowersDag.
  */
  template <typename Func> void apply(Func &&func) const {
    if (!is_configured()) {
      throw std::logic_error("PowersDag has not been configured");
    }

    for (std::uint32_t power : target_powers_) {
      func(nodes_.at(power));
    }
  }

  /**
        Applies a function in a topological order to each node in the PowersDag
     using multiple threads.
        */
  template <typename Func> void parallel_apply(Func &&func) const {
    if (!is_configured()) {
      throw std::logic_error("PowersDag has not been configured");
    }

    // Create a temporary vector of target powers instead so we can index into
    // it
    std::vector<std::uint32_t> target_powers_vec(target_powers_.cbegin(),
                                                 target_powers_.cend());
    std::size_t target_powers_count = target_powers_vec.size();

    ThreadPoolMgr tpm;

    enum class NodeState { Uncomputed = 0, Computing = 1, Computed = 2 };

    // Initialize all nodes as uncomputed
    std::unique_ptr<std::atomic<NodeState>[]> node_states(
        new std::atomic<NodeState>[target_powers_count]);
    for (std::size_t power_idx = 0; power_idx < target_powers_count;
         power_idx++) {
      node_states[power_idx].store(NodeState::Uncomputed);
    }

    auto node_worker = [&]() {
      // Start looking for work by going over node_states vector
      std::size_t power_idx = 0;
      while (true) {
        // Check if everything is done
        bool done = std::all_of(
            node_states.get(), node_states.get() + target_powers_count,
            [](auto &node_state) { return node_state == NodeState::Computed; });
        if (done) {
          return;
        }

        std::uint32_t power = target_powers_vec[power_idx];
        NodeState state = NodeState::Uncomputed;
        bool cmp = node_states[power_idx].compare_exchange_strong(
            state, NodeState::Computing);

        if (!cmp) {
          // Either done or already being processed
          power_idx = (power_idx + 1) % target_powers_count;
          continue;
        }

        // Get the current node
        auto node = nodes_.at(power);

        // If this is a source we can immediately process it
        if (node.is_source()) {
          // We can immediately process a source node
          func(nodes_.at(power));

          // Done with this source node; mark it as computed
          state = NodeState::Computing;
          node_states[power_idx].compare_exchange_strong(state,
                                                         NodeState::Computed);

          // Move on to the next node
          power_idx = (power_idx + 1) % target_powers_count;
          continue;
        }

        // Next check if parents have been computed; start by finding the parent
        // powers
        std::uint32_t p1 = node.parents.first;
        std::uint32_t p2 = node.parents.second;

        // The parents are always found in target_powers_vec
        auto p1_power_iter =
            std::find(target_powers_vec.cbegin(), target_powers_vec.cend(), p1);
        auto p2_power_iter =
            std::find(target_powers_vec.cbegin(), target_powers_vec.cend(), p2);
        if (p1_power_iter == target_powers_vec.cend() ||
            p2_power_iter == target_powers_vec.cend()) {
          throw std::runtime_error("PowersDag is in an invalid state");
        }

        // Compute the locations in node_states
        std::size_t p1_power_idx = static_cast<std::size_t>(
            std::distance(target_powers_vec.cbegin(), p1_power_iter));
        std::size_t p2_power_idx = static_cast<std::size_t>(
            std::distance(target_powers_vec.cbegin(), p2_power_iter));

        // Are the parents computed?
        bool p1_computed = node_states[p1_power_idx] == NodeState::Computed;
        bool p2_computed = node_states[p2_power_idx] == NodeState::Computed;

        if (!(p1_computed && p2_computed)) {
          // Parents are not done
          NodeState computing_state = NodeState::Computing;
          node_states[power_idx].compare_exchange_strong(computing_state,
                                                         NodeState::Uncomputed);

          // Move on to the next node
          power_idx = (power_idx + 1) % target_powers_count;
          continue;
        }

        // Parents are done so process this node
        func(nodes_.at(power));

        // Done with this node; mark it as computed
        state = NodeState::Computing;
        node_states[power_idx].compare_exchange_strong(state,
                                                       NodeState::Computed);

        // Move on to the next node
        power_idx = (power_idx + 1) % target_powers_count;
      }
    };

    std::size_t task_count = ThreadPoolMgr::GetThreadCount();
    std::vector<std::future<void>> futures(task_count);
    for (std::size_t t = 0; t < task_count; t++) {
      futures[t] = tpm.thread_pool().enqueue(node_worker);
    }

    for (auto &f : futures) {
      f.get();
    }
  }

  /**
  Creates a new PowersDag instance by copying a given one.
  */
  PowersDag(const PowersDag &pd) = default;

private:
  std::unordered_map<std::uint32_t, PowersNode> nodes_;

  bool configured_ = false;

  std::set<std::uint32_t> target_powers_;

  std::uint32_t depth_;

  std::uint32_t source_count_;

  unsigned int total_multiplications = 0;
};

bool PowersDag::configure(set<uint32_t> &source_powers,
                          set<uint32_t> &target_powers) {
  reset();

  // Source powers cannot contain 0 and must contain 1
  if (source_powers.find(0) != source_powers.cend() ||
      source_powers.find(1) == source_powers.cend()) {
    return false;
  }

  // Target powers cannot contain 0 and must contain 1
  if (target_powers.find(0) != target_powers.cend() ||
      target_powers.find(1) == target_powers.cend()) {
    return false;
  }

  // Source powers must be a subset of target powers
  if (!includes(target_powers.cbegin(), target_powers.cend(),
                source_powers.cbegin(), source_powers.cend())) {
    return false;
  }

  // Insert all source nodes
  for (uint32_t s : source_powers) {
    nodes_[s] = PowersNode{/* power */ s, /* depth */ 0};
  }

  // Keep track of the largest encountered depth
  uint32_t curr_depth = 0;

  // Now compute the non-source powers
  for (uint32_t curr_power : target_powers) {
    // Do nothing if this is a source power
    if (source_powers.find(curr_power) != source_powers.cend()) {
      continue;
    }

    // The current power should be written as a sum of two lower powers in a
    // depth-optimal way.
    uint32_t optimal_depth = curr_power - 1;
    uint32_t optimal_s1 = curr_power - 1;
    uint32_t optimal_s2 = 1;

    // Loop over possible values for the first parent
    for (uint32_t s1 : target_powers) {
      // Only go up to the current target power for the first parent
      if (s1 >= curr_power) {
        break;
      }

      // Second parent is fully determined and must be a target power as well
      uint32_t s2 = curr_power - s1;
      if (target_powers.find(s2) == target_powers.cend()) {
        continue;
      }

      // Compute the depth for this choice of parents for the current power
      uint32_t depth = max(nodes_.at(s1).depth, nodes_.at(s2).depth) + 1;

      // Is this choice for the parents better than any we saw before?
      if (depth < optimal_depth) {
        optimal_depth = depth;
        optimal_s1 = s1;
        optimal_s2 = s2;
      }
    }

    // We have found an optimal way to obtain the current power from two lower
    // powers. Now add data for the new node.
    nodes_[curr_power] = PowersNode{curr_power, optimal_depth,
                                    make_pair(optimal_s1, optimal_s2)};

    // Update the number of multiplications. If s1 or s2 are a source, then the
    // number of additional multiplications is 1.

    // The maximal required depth is updated according to the depth of the newly
    // added node.
    curr_depth = max(curr_depth, optimal_depth);
  }

  // Success
  configured_ = true;
  target_powers_ = target_powers;
  depth_ = curr_depth;
  source_count_ = static_cast<uint32_t>(source_powers.size());
  return true;
}

set<uint32_t> PowersDag::target_powers() const {
  if (!configured_) {
    throw logic_error("PowersDag has not been configured");
  }
  return target_powers_;
}

uint32_t PowersDag::depth() const {
  if (!configured_) {
    throw logic_error("PowersDag has not been configured");
  }
  return depth_;
}

uint32_t PowersDag::source_count() const {
  if (!configured_) {
    throw logic_error("PowersDag has not been configured");
  }
  return source_count_;
}

vector<PowersDag::PowersNode> PowersDag::source_nodes() const {
  if (!configured_) {
    throw logic_error("PowersDag has not been configured");
  }

  vector<PowersNode> result;
  for (auto &node : nodes_) {
    if (!node.second.parents.first && !node.second.parents.second) {
      result.push_back(node.second);
    }
  }

  return result;
}

string PowersDag::to_dot() const {
  if (!configured_) {
    throw logic_error("PowersDag has not been configured");
  }

  stringstream ss;
  ss << "digraph powers {" << endl;
  for (auto &node : nodes_) {
    // Add the node
    uint32_t power = node.second.power;
    ss << "\t" << power << ";" << endl;

    // Add the two parent edges if they are non-zero
    auto p1 = node.second.parents.first;
    auto p2 = node.second.parents.second;
    if (p1) {
      ss << "\t" << power << " -> " << p1 << ";" << endl;
    }
    if (p2) {
      ss << "\t" << power << " -> " << p2 << ";" << endl;
    }
  }

  ss << "}" << endl;

  return ss.str();
}

void trim_sources(std::set<uint32_t> &sources,
                  const std::set<uint32_t> &targets) {
  uint32_t max_target = *std::max_element(targets.begin(), targets.end());
  // This will work starting in C++20
  // std::erase_if(sources, [](const auto & val){return val >= max_target;});
  // This is the C++17 version
  // Don't forget to capture!
  // std::remove_if(sources.begin(), sources.end(), [max_target](const uint32_t
  // val){return val >= max_target;});

  // None of the above worked, so here's a lazy 2-iteration solution
  set<uint32_t> trimees;
  for (const uint32_t x : sources) {
    if (x > max_target) {
      trimees.insert(x);
    }
  }
  for (const uint32_t y : trimees) {
    sources.erase(y);
  }
  return;
}

#endif