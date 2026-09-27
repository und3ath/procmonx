#include "pmx/append_log.h"

#include <thread>

#include "test_util.h"

int test_append_log() {
  int before = g_failures;
  pmx::AppendLog<int, 4> log;  // 16-element chunks to exercise chunk crossing
  CHECK(log.size() == 0);
  for (int i = 0; i < 100; ++i) CHECK(log.emplace_back(i * 3) == (size_t)i);
  CHECK(log.size() == 100);
  for (int i = 0; i < 100; ++i) CHECK(log[i] == i * 3);

  // Single-writer / single-reader concurrency: reader only touches published.
  pmx::AppendLog<size_t, 8> shared;
  std::thread w([&] {
    for (size_t i = 0; i < 50000; ++i) shared.emplace_back(i);
  });
  size_t seen = 0;
  while (seen < 50000) {
    size_t n = shared.size();
    for (; seen < n; ++seen) CHECK(shared[seen] == seen);
  }
  w.join();
  return g_failures - before;
}
