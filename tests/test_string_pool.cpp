#include "pmx/string_pool.h"

#include "test_util.h"

int test_string_pool() {
  int before = g_failures;
  pmx::StringPool pool;
  CHECK(pool.intern(L"") == 0);
  const uint32_t a = pool.intern(L"C:\\Windows\\System32");
  const uint32_t b = pool.intern(L"C:\\Windows\\System32");
  const uint32_t c = pool.intern(L"C:\\Users");
  CHECK(a == b);        // dedup
  CHECK(a != c);
  CHECK(pool.get(a) == L"C:\\Windows\\System32");
  CHECK(pool.get(c) == L"C:\\Users");
  CHECK(pool.get(0).empty());

  // Force a block spill.
  std::wstring big(2'000'000, L'x');
  const uint32_t big_id = pool.intern(big);
  CHECK(pool.get(big_id).size() == big.size());
  CHECK(pool.get(a) == L"C:\\Windows\\System32");  // earlier ref still valid
  return g_failures - before;
}
