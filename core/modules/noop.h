#ifndef __NOOP_H__
#define __NOOP_H__

#include "../module.h"
#include "../module_msg.pb.h"

class NoOP : public Module {
 public:
  virtual struct snobj *Init(struct snobj *arg);
  virtual pb_error_t InitPb(const bess::pb::EmptyArg &arg);

  virtual struct task_result RunTask(void *arg);

  static const gate_idx_t kNumIGates = 0;
  static const gate_idx_t kNumOGates = 0;

  static const Commands<Module> cmds;
  static const PbCommands pb_cmds;
};

#endif
