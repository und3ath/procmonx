#pragma once
// Turn a paired CompletedEvent + the ProcessTable into a fully decoded Event
// (process name, op/sub-op name, object path, and the formatted detail column).
// Shared by the CLI, the store, and future PML export / GUI.

#include "pmx/enrich/pairer.h"
#include "pmx/enrich/process_table.h"
#include "pmx/event.h"

namespace pmx {

Event decodeEvent(const CompletedEvent& ce, const ProcessTable& procs);

}  // namespace pmx
