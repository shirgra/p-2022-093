/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <bm/bm_sim/ageing.h>
#include <bm/bm_sim/match_tables.h>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/logger.h>

#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <map>
#include <unordered_set>
#include <vector>
#include <memory>

namespace bm {

static_assert(sizeof(AgeingMonitorIface::msg_hdr_t) == 32u,
              "Invalid size for ageing notification header");

class AgeingMonitor final : public AgeingMonitorIface {
 public:
  using msg_hdr_t = AgeingMonitorIface::msg_hdr_t;
  using buffer_id_t = uint64_t;
  using clock = Packet::clock;

  AgeingMonitor(device_id_t device_id, cxt_id_t cxt_id,
                std::shared_ptr<TransportIface> writer,
                unsigned int sweep_interval_ms = 1000u);

  ~AgeingMonitor();

  void add_table(MatchTableAbstract *table) override;

  void add_stateful_table(StatefulTable *table) override;

  void set_sweep_interval(unsigned int ms) override;

  unsigned int get_sweep_interval() override;

  void reset_state() override;

  std::string get_table_name_from_id(p4object_id_t id) const override;

 private:
  void sweep_loop();
  void do_sweep();

 private:
  struct TableData {
    explicit TableData(MatchTableAbstract *table)
      : table(table) { }

    TableData(const TableData &other) = delete;
    TableData &operator=(const TableData &other) = delete;

    TableData(TableData &&other) /*noexcept*/ = default;
    TableData &operator=(TableData &&other) /*noexcept*/ = default;

    MatchTableAbstract *table{nullptr};
    std::unordered_set<entry_handle_t> prev_sweep_entries{};
  };

 private:
  mutable std::mutex mutex{};

  std::map<p4object_id_t, TableData> tables_with_ageing{};

  std::vector<StatefulTable *> stateful_tables_with_ageing{};

  device_id_t device_id{};
  cxt_id_t cxt_id{};

  std::shared_ptr<TransportIface> writer{nullptr};

  std::atomic<unsigned int> sweep_interval_ms{0};

  std::vector<entry_handle_t> entries{};
  std::vector<entry_handle_t> entries_tmp{};
  buffer_id_t buffer_id{0};

  std::thread sweep_thread{};
  bool stop_sweep_thread{false};
  mutable std::condition_variable stop_condvar{};
};

AgeingMonitor::AgeingMonitor(device_id_t device_id, cxt_id_t cxt_id,
                             std::shared_ptr<TransportIface> writer,
                             unsigned int sweep_interval_ms)
    : device_id(device_id), cxt_id(cxt_id), writer(writer),
      sweep_interval_ms(sweep_interval_ms) {
  sweep_thread = std::thread(&AgeingMonitor::sweep_loop, this);
}

AgeingMonitor::~AgeingMonitor() {
  {
    std::unique_lock<std::mutex> lock(mutex);
    stop_sweep_thread = true;
  }
  stop_condvar.notify_one();
  sweep_thread.join();
}

void
AgeingMonitor::add_table(MatchTableAbstract *table) {
  tables_with_ageing.insert(std::make_pair(table->get_id(), TableData(table)));
}

void
AgeingMonitor::add_stateful_table(StatefulTable *table) {
  stateful_tables_with_ageing.push_back(table);
}

void
AgeingMonitor::set_sweep_interval(unsigned int ms) {
  std::unique_lock<std::mutex> lock(mutex);
  sweep_interval_ms = ms;
}

unsigned int
AgeingMonitor::get_sweep_interval() {
  std::unique_lock<std::mutex> lock(mutex);
  return sweep_interval_ms;
}

void
AgeingMonitor::reset_state() {
  std::unique_lock<std::mutex> lock(mutex);
  entries.clear();
  entries_tmp.clear();
  buffer_id = 0;
  for (auto &entry : tables_with_ageing) {
    TableData &data = entry.second;
    data.prev_sweep_entries.clear();
  }
}

std::string
AgeingMonitor::get_table_name_from_id(p4object_id_t id) const {
  // we use a std::map, but lookup should be fast for such a small map
  auto it = tables_with_ageing.find(id);
  if (it == tables_with_ageing.end()) return "";
  return it->second.table->get_name();
}

void
AgeingMonitor::sweep_loop() {
  using std::chrono::milliseconds;
  auto tp = clock::now();
  std::unique_lock<std::mutex> lock(mutex);
  while (!stop_sweep_thread) {
    do_sweep();
    milliseconds interval(sweep_interval_ms);
    tp += interval;
    stop_condvar.wait_until(lock, tp);
  }
}

void
AgeingMonitor::do_sweep() {
  for (auto & t : stateful_tables_with_ageing) {
    t->get_match_table()->sweep_entries(&entries_tmp);

    if (!entries_tmp.empty()) {
      for (entry_handle_t handle : entries_tmp) {
        t->delete_entry(handle);
        BMLOG_DEBUG(" [Stateful Ageing]  Deleting entry #{} in {}",
                    handle, t->get_name())
      }
      entries_tmp.clear();
    }
  }

  for (auto &entry : tables_with_ageing) {
    TableData &data = entry.second;
    const MatchTableAbstract *t = data.table;
    auto &prev_sweep_entries = data.prev_sweep_entries;

    t->sweep_entries(&entries_tmp);
    if (entries_tmp.empty()) {
      prev_sweep_entries.clear();
      continue;
    }

    for (entry_handle_t handle : entries_tmp) {
      if (prev_sweep_entries.find(handle) == prev_sweep_entries.end()) {
        BMLOG_TRACE("Ageing entry {} in table '{}'\n", handle, t->get_name());
        entries.push_back(handle);
      }
    }
    entries_tmp.clear();
    prev_sweep_entries.clear();

    if (entries.empty()) continue;

    for (entry_handle_t handle : entries) {
      prev_sweep_entries.insert(handle);
    }

    BMLOG_TRACE("Sending ageing notification for table '{}' ({})",
                t->get_name(), entry.first);

    unsigned int num_entries = static_cast<unsigned int>(entries.size());
    unsigned int size =
      static_cast<unsigned int>(num_entries * sizeof(entry_handle_t));

    msg_hdr_t msg_hdr;
    char *msg_hdr_ = reinterpret_cast<char *>(&msg_hdr);
    memset(msg_hdr_, 0, sizeof(msg_hdr));
    memcpy(msg_hdr_, "AGE|", 4);
    msg_hdr.switch_id = device_id;
    msg_hdr.cxt_id = cxt_id;
    msg_hdr.buffer_id = buffer_id++;
    msg_hdr.table_id = entry.first;
    msg_hdr.num_entries = num_entries;

    TransportIface::MsgBuf buf_hdr =
      {reinterpret_cast<char *>(&msg_hdr), sizeof(msg_hdr)};
    TransportIface::MsgBuf buf_entries =
      {reinterpret_cast<char *>(entries.data()), size};
    writer->send_msgs({buf_hdr, buf_entries});
    entries.clear();
  }
}

std::unique_ptr<AgeingMonitorIface>
AgeingMonitorIface::make(device_id_t device_id, cxt_id_t cxt_id,
                         std::shared_ptr<TransportIface> writer,
                         unsigned int sweep_interval_ms) {
  return std::unique_ptr<AgeingMonitorIface>(new AgeingMonitor(
      device_id, cxt_id, writer, sweep_interval_ms));
}

}  // namespace bm
