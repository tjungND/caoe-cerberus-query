#ifndef THREAD_POOL_MGR_H
#define THREAD_POOL_MGR_H

#include <cstddef>

#include "thread_pool.h"

class ThreadPoolMgr {
public:
  /**
  Build an instance of ThreadPoolMgr
  */
  ThreadPoolMgr();

  /**
  Destructor for ThreadPoolMgr
  */
  ~ThreadPoolMgr();

  /**
  Get the thread pool managed by the thread pool manager
  */
  ThreadPool &thread_pool() const;

  /**
  Set the number of threads to be used by the thread pool
  */
  static void SetThreadCount(std::size_t threads);

  /**
  This method is to be used explicitly by tests.
  */
  static void SetPhysThreadCount(std::size_t threads);

  /**
  Get the number of threads used by the thread pool
  */
  static std::size_t GetThreadCount();

private:
  /**
  Reference count to manage lifetime of the static thread pool
  */
  static std::size_t ref_count_;
};

/**
Static reference count that will manage the lifetime of the single ThreadPool
object that all users of this class will share.
*/
size_t ThreadPoolMgr::ref_count_ = 0;

namespace {
mutex tp_mutex;
size_t thread_count = thread::hardware_concurrency();
size_t phys_thread_count = thread::hardware_concurrency();
unique_ptr<ThreadPool> thread_pool_;
} // namespace

ThreadPoolMgr::ThreadPoolMgr() {
  unique_lock<mutex> lock(tp_mutex);

  if (ref_count_ == 0) {
    thread_pool_ = make_unique<ThreadPool>(phys_thread_count);
  }

  ref_count_++;
}

ThreadPoolMgr::~ThreadPoolMgr() {
  unique_lock<mutex> lock(tp_mutex);

  ref_count_--;
  if (ref_count_ == 0) {
    thread_pool_ = nullptr;
  }
}

ThreadPool &ThreadPoolMgr::thread_pool() const {
  if (!thread_pool_)
    throw runtime_error("Thread pool is not available");

  return *thread_pool_;
}

void ThreadPoolMgr::SetThreadCount(size_t threads) {
  unique_lock<mutex> lock(tp_mutex);

  thread_count = threads != 0 ? threads : thread::hardware_concurrency();
  phys_thread_count = thread_count;

  if (thread_pool_) {
    thread_pool_->set_pool_size(phys_thread_count);
  }
}

void ThreadPoolMgr::SetPhysThreadCount(size_t threads) {
  unique_lock<mutex> lock(tp_mutex);

  phys_thread_count = threads != 0 ? threads : thread::hardware_concurrency();

  if (thread_pool_) {
    thread_pool_->set_pool_size(phys_thread_count);
  }
}

size_t ThreadPoolMgr::GetThreadCount() { return thread_count; }

#endif