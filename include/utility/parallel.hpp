#pragma once

#ifndef __UTILITY_PARALLEL_HPP__
#define __UTILITY_PARALLEL_HPP__

#include <range/v3/all.hpp>
#include <thread>
#include <future>

namespace par {
    using namespace ranges;

    auto size(size_t n) { return n / (std::thread::hardware_concurrency()); }
    template<class Con>
    auto csize(Con container) { return container.size() / (std::thread::hardware_concurrency()); }
    template<class Range>
    auto rsize(Range rng) { return distance(rng) / (std::thread::hardware_concurrency()); }

    template<class Func>
    auto iter(size_t n, Func&& func) {
        return make_pipeable([&](auto&& rngs) {//using Rngs = decltype(rngs);
            return rngs
                | views::chunk(n)
                | views::transform([&](auto it) {
                        return std::async(std::launch::async,[&](){ return it | func; });})
                | views::transform([](auto it){ return std::move(it.get()); })
                | views::join;
        });
    }

    template<class Func>
    auto transform(size_t n, Func&& func) {
        return views::chunk(n)
             | views::transform([&](auto it) {
                     return std::async(std::launch::async,[&](auto it){return it|views::transform(func);},it);})
             | views::transform([](auto it ){ return it.get(); })
             | views::cache1
             | views::join ;
    }

    template<class Func>
    auto for_each(size_t n, Func&& func) {
        return views::chunk(n)
             | views::transform([&](auto it) {
                     return std::async(std::launch::async,[&](auto it){return it|views::for_each(func);},it);})
             | views::transform([](auto it ){ return it.get(); })
             | views::cache1
             | views::join ;
    }
}


#endif
