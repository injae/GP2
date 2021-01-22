#pragma once

#ifndef __SIMNET_NONE_BLOCKING_QUEUE_HPP__
#define __SIMNET_NONE_BLOCKING_QUEUE_HPP__

#include <atomic>
#include <deque>
#include <string>
#include <mutex>

namespace simnet {
    class atomic_mutex {
        std::atomic_flag flag{ATOMIC_FLAG_INIT};
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

    private:
        std::deque<T> queue_;
        atomic_mutex mtx;
    };
};


#endif
