#pragma once

#include <stddef.h>
#include <vector>
#include <string>
#include <map>
#include <memory>
#include <set>
#include <tuple>
#include <utility>

#include "vm/cells.h"
#include "vm/dict.h"
#include "block/mc-config.h"
#include "block/transaction.h"
#include "impl/shard.hpp"
#include "block-auto.h"
#include "block.h"
#include "common/bigint.hpp"
#include "common/bitstring.h"
#include "common/refcnt.hpp"
#include "common/refint.h"
#include "interfaces/message-queue.h"
#include "interfaces/shard.h"
#include "actor/ActorId.h"
#include "actor/PromiseFuture.h"
#include "actor/common.h"
#include "actor/core/Actor.h"
#include "utils/Status.h"
#include "utils/buffer.h"
#include "utils/int_types.h"
#include "utils/logging.h"
#include "ton/ton-types.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellSlice.h"

namespace vm {
class CellBuilder;
class CellUsageTree;
}  // namespace vm

namespace solution {

using namespace ton;
using namespace ton::validator;

using td::Ref;

class ErrorCtxAdd;
class ErrorCtxSet;

struct ErrorCtx {
 protected:
  friend class ErrorCtxAdd;
  friend class ErrorCtxSet;
  std::vector<std::string> entries_;

 public:
  ErrorCtx() = default;
  ErrorCtx(std::vector<std::string> str_list) : entries_(std::move(str_list)) {
  }
  ErrorCtx(std::string str) : entries_{str} {
  }
  std::string as_string() const;
  ErrorCtxAdd add_guard(std::string str_add);
  ErrorCtxSet set_guard(std::string str);
  ErrorCtxSet set_guard(std::vector<std::string> str_list);
};

class ErrorCtxAdd {
  ErrorCtx& ctx_;

 public:
  ErrorCtxAdd(ErrorCtx& ctx, std::string ctx_elem) : ctx_(ctx) {
    ctx_.entries_.push_back(std::move(ctx_elem));
  }
  ~ErrorCtxAdd() {
    ctx_.entries_.pop_back();
  }
};

class ErrorCtxSet {
  ErrorCtx& ctx_;
  std::vector<std::string> old_ctx_;

 public:
  ErrorCtxSet(ErrorCtx& ctx, std::vector<std::string> new_ctx) : ctx_(ctx) {
    old_ctx_ = std::move(ctx_.entries_);
    ctx_.entries_ = std::move(new_ctx);
  }
  ErrorCtxSet(ErrorCtx& ctx, std::string new_ctx) : ErrorCtxSet(ctx, std::vector<std::string>{new_ctx}) {
  }
  ~ErrorCtxSet() {
    ctx_.entries_ = std::move(old_ctx_);
  }
};

inline ErrorCtxAdd ErrorCtx::add_guard(std::string str) {
  return ErrorCtxAdd(*this, std::move(str));
}

inline ErrorCtxSet ErrorCtx::set_guard(std::string str) {
  return ErrorCtxSet(*this, std::move(str));
}

inline ErrorCtxSet ErrorCtx::set_guard(std::vector<std::string> str_list) {
  return ErrorCtxSet(*this, std::move(str_list));
}

class ContestValidateQuery : public td::actor::Actor {
  static constexpr int supported_version() {
    return SUPPORTED_VERSION;
  }
  static constexpr long long supported_capabilities() {
    return ton::capCreateStatsEnabled | ton::capBounceMsgBody | ton::capReportVersion | ton::capShortDequeue |
           ton::capStoreOutMsgQueueSize | ton::capMsgMetadata | ton::capDeferMessages | ton::capFullCollatedData;
  }

 public:
  ContestValidateQuery(BlockIdExt block_id, td::BufferSlice block_data, td::BufferSlice collated_data,
                       td::Promise<td::BufferSlice> promise);

 private:
  int verbosity{0};
  int pending{0};
  const ShardIdFull shard_;
  const BlockIdExt id_;
  std::vector<BlockIdExt> prev_blocks;
  std::vector<Ref<ShardState>> prev_states;
  td::BufferSlice block_data, collated_data;
  td::Promise<td::BufferSlice> main_promise;
  bool after_merge_{false};
  bool after_split_{false};
  bool before_split_{false};
  bool want_split_{false};
  bool want_merge_{false};
  bool is_key_block_{false};
  bool update_shard_cc_{false};
  bool prev_key_block_exists_{false};
  bool debug_checks_{false};
  bool outq_cleanup_partial_{false};
  BlockSeqno prev_key_seqno_{~0u};
  int stage_{0};
  td::BitArray<64> shard_pfx_;
  int shard_pfx_len_;
  td::Bits256 created_by_;

  Ref<vm::Cell> prev_state_root_;
  std::shared_ptr<vm::CellUsageTree> state_usage_tree_;  // used to construct Merkle update

  ErrorCtx error_ctx_;

  td::Ref<MasterchainStateQ> mc_state_;
  td::Ref<vm::Cell> mc_state_root_;
  BlockIdExt mc_blkid_;
  ton::BlockSeqno mc_seqno_{0};

  Ref<vm::Cell> block_root_;
  Ref<vm::Cell> value_flow_root_;
  std::vector<Ref<vm::Cell>> collated_roots_;
  std::map<RootHash, Ref<vm::Cell>> virt_roots_;
  bool top_shard_descr_dict_;
  block::gen::ExtraCollatedData::Record extra_collated_data_;
  bool have_extra_collated_data_ = false;

  Ref<vm::Cell> recover_create_msg_, mint_msg_;  // from McBlockExtra (UNCHECKED)

  std::unique_ptr<block::ConfigInfo> config_;
  std::unique_ptr<block::ShardConfig> old_shard_conf_;  // from reference mc state
  std::unique_ptr<block::ShardConfig> new_shard_conf_;  // from shard_hashes_ in mc blocks
  Ref<block::WorkchainInfo> wc_info_;
  Ref<vm::Cell> old_mparams_;
  bool accept_msgs_{true};

  ton::BlockSeqno min_shard_ref_mc_seqno_{~0U};
  ton::LogicalTime max_shard_lt_{0};

  int global_id_{0};
  ton::BlockSeqno vert_seqno_{~0U};
  bool ihr_enabled_{false};
  bool create_stats_enabled_{false};
  ton::BlockSeqno prev_key_block_seqno_;
  ton::BlockIdExt prev_key_block_;
  ton::LogicalTime prev_key_block_lt_;
  std::unique_ptr<block::BlockLimits> block_limits_;
  std::unique_ptr<block::BlockLimitStatus> block_limit_status_;
  td::uint64 total_gas_used_{0}, total_special_gas_used_{0};

  LogicalTime start_lt_, end_lt_;
  UnixTime now_{~0u};

  ton::Bits256 rand_seed_;
  std::vector<block::StoragePrices> storage_prices_;
  block::StoragePhaseConfig storage_phase_cfg_{&storage_prices_};
  block::ComputePhaseConfig compute_phase_cfg_;
  block::ActionPhaseConfig action_phase_cfg_;
  td::RefInt256 masterchain_create_fee_, basechain_create_fee_;

  std::vector<block::McShardDescr> neighbors_;
  std::map<BlockSeqno, Ref<MasterchainStateQ>> aux_mc_states_;

  block::ShardState ps_;
  block::ShardState ns_;
  bool processed_upto_updated_{false};
  std::unique_ptr<vm::AugmentedDictionary> sibling_out_msg_queue_;
  std::shared_ptr<block::MsgProcessedUptoCollection> sibling_processed_upto_;

  std::map<td::Bits256, int> block_create_count_;
  unsigned block_create_total_{0};

  std::unique_ptr<vm::AugmentedDictionary> in_msg_dict_, out_msg_dict_, account_blocks_dict_;
  block::ValueFlow value_flow_;
  block::CurrencyCollection import_created_, transaction_fees_, total_burned_{0}, fees_burned_{0};
  td::RefInt256 import_fees_;

  ton::LogicalTime proc_lt_{0}, claimed_proc_lt_{0}, min_enq_lt_{~0ULL};
  ton::Bits256 proc_hash_ = ton::Bits256::zero(), claimed_proc_hash_, min_enq_hash_;

  std::vector<std::tuple<Bits256, LogicalTime, LogicalTime>> msg_proc_lt_;
  std::vector<std::tuple<Bits256, LogicalTime, LogicalTime>> msg_emitted_lt_;

  std::map<std::pair<StdSmcAddress, td::uint64>, Ref<vm::Cell>> removed_dispatch_queue_messages_;
  std::map<std::pair<StdSmcAddress, td::uint64>, Ref<vm::Cell>> new_dispatch_queue_messages_;
  std::set<StdSmcAddress> account_expected_defer_all_messages_;
  td::uint64 old_out_msg_queue_size_ = 0;
  bool out_msg_queue_size_known_ = false;
  bool have_out_msg_queue_size_in_state_ = false;

  bool msg_metadata_enabled_ = false;
  bool deferring_messages_enabled_ = false;
  bool store_out_msg_queue_size_ = false;

  td::uint64 processed_account_dispatch_queues_ = 0;
  bool have_unprocessed_account_dispatch_queue_ = false;

  WorkchainId workchain() const {
    return shard_.workchain;
  }

  void finish_query();
  void abort_query(td::Status error);
  bool reject_query(std::string error, td::BufferSlice reason = {});
  bool reject_query(std::string err_msg, td::Status error, td::BufferSlice reason = {});
  bool soft_reject_query(std::string error, td::BufferSlice reason = {});
  void start_up() override;

  bool unpack_block_data_func();
  bool unpack_collated_data_func();

  bool fatal_error(td::Status error);
  bool fatal_error(int err_code, std::string err_msg);
  bool fatal_error(int err_code, std::string err_msg, td::Status error);
  bool fatal_error(std::string err_msg, int err_code = -666);

  std::string error_ctx() const {
    return error_ctx_.as_string();
  }
  ErrorCtxAdd error_ctx_add_guard(std::string str) {
    return error_ctx_.add_guard(std::move(str));
  }
  ErrorCtxSet error_ctx_set_guard(std::string str) {
    return error_ctx_.set_guard(std::move(str));
  }

  td::actor::ActorId<ContestValidateQuery> get_self() {
    return actor_id(this);
  }

  std::map<BlockIdExt, Ref<ShardState>> fetched_states_;

  td::Result<Ref<ShardState>> fetch_block_state(BlockIdExt block_id) {
    auto fetched_state = fetched_states_.find(block_id);
    if (fetched_state == fetched_states_.end()) {
      Ref<vm::Cell> state_root = get_virt_state_root(block_id.root_hash);
      if (state_root.is_null()) {
        return td::Status::Error(PSTRING() << "cannot get hash of state root: " << block_id.to_str());
      }
      td::Bits256 state_root_hash = state_root->get_hash().bits();
      auto it = virt_roots_.find(state_root_hash);
      if (it == virt_roots_.end()) {
        return td::Status::Error(PSTRING() << "cannot get state root from collated data: " << block_id.to_str());
      }
      TRY_RESULT(res, ShardStateQ::fetch(block_id, {}, it->second));
      fetched_states_[block_id] = res;
    }
    return td::Result<Ref<ShardState>>(fetched_states_[block_id]);
  }

  void after_get_mc_state(td::Result<Ref<ShardState>> res);
  void after_get_shard_state(int idx, td::Result<Ref<ShardState>> res);
  bool process_mc_state(Ref<MasterchainState> mc_state);
  bool try_unpack_mc_state();
  bool fetch_config_params();
  bool check_prev_block(const BlockIdExt& listed, const BlockIdExt& prev, bool chk_chain_len = true);
  bool check_prev_block_exact(const BlockIdExt& listed, const BlockIdExt& prev);
  bool check_this_shard_mc_info();
  bool init_parse();
  bool unpack_block_candidate();
  bool extract_collated_data_from(Ref<vm::Cell> croot, int idx);
  bool extract_collated_data();
  bool try_validate();
  bool compute_prev_state();
  bool unpack_merge_prev_state();
  bool unpack_prev_state();
  bool init_next_state();
  bool unpack_one_prev_state(block::ShardState& ss, BlockIdExt blkid, Ref<vm::Cell> prev_state_root);
  bool split_prev_state(block::ShardState& ss);
  bool request_neighbor_queues();
  void got_neighbor_out_queue(int i, td::Result<Ref<MessageQueue>> res);

  bool register_mc_state(Ref<MasterchainStateQ> other_mc_state);
  bool request_aux_mc_state(BlockSeqno seqno, Ref<MasterchainStateQ>& state);
  Ref<MasterchainStateQ> get_aux_mc_state(BlockSeqno seqno) const;
  void after_get_aux_shard_state(ton::BlockIdExt blkid, td::Result<Ref<ShardState>> res);

  bool check_utime_lt();
  bool prepare_out_msg_queue_size();
  void got_out_queue_size(size_t i, td::Result<td::uint64> res);

  bool fix_one_processed_upto(block::MsgProcessedUpto& proc, ton::ShardIdFull owner, bool allow_cur = false);
  bool fix_processed_upto(block::MsgProcessedUptoCollection& upto, bool allow_cur = false);
  bool fix_all_processed_upto();
  bool add_trivial_neighbor_after_merge();
  bool add_trivial_neighbor();
  bool unpack_block_data();
  bool unpack_precheck_value_flow();
  bool compute_minted_amount(block::CurrencyCollection& to_mint);
  bool postcheck_one_account_update(td::ConstBitPtr acc_id, Ref<vm::CellSlice> old_value, Ref<vm::CellSlice> new_value);
  bool postcheck_account_updates();
  bool precheck_one_transaction(td::ConstBitPtr acc_id, ton::LogicalTime trans_lt, Ref<vm::CellSlice> trans_csr,
                                ton::Bits256& prev_trans_hash, ton::LogicalTime& prev_trans_lt,
                                unsigned& prev_trans_lt_len, ton::Bits256& acc_state_hash);
  bool precheck_one_account_block(td::ConstBitPtr acc_id, Ref<vm::CellSlice> acc_blk);
  bool precheck_account_transactions();
  Ref<vm::Cell> lookup_transaction(const ton::StdSmcAddress& addr, ton::LogicalTime lt) const;
  bool is_valid_transaction_ref(Ref<vm::Cell> trans_ref) const;

  bool build_new_message_queue();
  bool precheck_one_message_queue_update(td::ConstBitPtr out_msg_id, Ref<vm::CellSlice> old_value,
                                         Ref<vm::CellSlice> new_value);
  bool precheck_message_queue_update();
  bool check_account_dispatch_queue_update(td::Bits256 addr, Ref<vm::CellSlice> old_queue_csr,
                                           Ref<vm::CellSlice> new_queue_csr);
  bool unpack_dispatch_queue_update();
  bool update_max_processed_lt_hash(ton::LogicalTime lt, const ton::Bits256& hash);
  bool update_min_enqueued_lt_hash(ton::LogicalTime lt, const ton::Bits256& hash);
  bool check_imported_message(Ref<vm::Cell> msg_env);
  bool is_special_in_msg(const vm::CellSlice& in_msg) const;
  bool check_in_msg(td::ConstBitPtr key, Ref<vm::CellSlice> in_msg);
  bool check_in_msg_descr();
  bool check_out_msg(td::ConstBitPtr key, Ref<vm::CellSlice> out_msg);
  bool check_out_msg_descr();
  bool check_dispatch_queue_update();
  bool check_processed_upto();
  bool check_neighbor_outbound_message(Ref<vm::CellSlice> enq_msg, ton::LogicalTime lt, td::ConstBitPtr key,
                                       const block::McShardDescr& src_nb, bool& unprocessed, bool& processed_here,
                                       td::Bits256& msg_hash);
  bool check_in_queue();
  std::unique_ptr<block::Account> make_account_from(td::ConstBitPtr addr, Ref<vm::CellSlice> account);
  std::unique_ptr<block::Account> unpack_account(td::ConstBitPtr addr);
  bool check_one_transaction(block::Account& account, LogicalTime lt, Ref<vm::Cell> trans_root, bool is_first,
                             bool is_last);
  bool check_account_transactions(const StdSmcAddress& acc_addr, Ref<vm::CellSlice> acc_tr);
  bool check_transactions();
  bool check_message_processing_order();
  bool check_new_state();
  bool postcheck_value_flow();

  Ref<vm::Cell> get_virt_state_root(td::Bits256 block_root_hash);

  td::BufferSlice result_state_update_;

  bool store_master_ref(vm::CellBuilder& cb);
  bool build_state_update();
};

}  // namespace solution