#pragma once

#ifndef __SIMNET_NONE_BLOCKING_QUEUE_HPP__
#define __SIMNET_NONE_BLOCKING_QUEUE_HPP__

#include <atomic>
#include <deque>
#include <string>
#include <mutex>
#include <future>
#include <condition_variable>

namespace simnet {
    class atomic_mutex {
        std::atomic_flag flag{false};
    public:
        void lock() { while(flag.test_and_set()) {} }
        void unlock() { flag.clear(); }
    };

    template<typename T>
    class queue {
    public:
        void push(T data) {
            std::lock_guard<atomic_mutex> lock{mtx};
            queue_.push_back(std::move(data));
        }
        T pop() {
            std::lock_guard<atomic_mutex> lock{mtx};
            T result = queue_.front();
            queue_.pop_front();
            return result;
        }

        bool empty() {
            std::lock_guard<atomic_mutex> lock{mtx};
            return queue_.empty();
        }

        std::future<T> wait_get() {
            return std::async([this](){ while(empty()) { } return pop(); });
        }

    private:
        std::deque<T> queue_;
        atomic_mutex mtx;
    };

    template<typename T>
    class block_queue {
    public:
        void push(T data) {
          {
            std::lock_guard lock{mtx};
            queue_.push_back(std::move(data));
          }
          cv.notify_one();
        }
        T pop() {
            std::unique_lock lock{mtx};
            cv.wait(lock, [&]{ return not queue_.empty(); });
            T result = queue_.front();
            queue_.pop_front();
            return result;
        }

        bool empty() {
            std::lock_guard lock{mtx};
            return queue_.empty();
        }

        std::future<T> wait_get() {
            return std::async([this](){ return pop(); });
        }

    private:
        std::deque<T> queue_;
        std::mutex mtx;
        std::condition_variable cv;
    };
};


#endif
