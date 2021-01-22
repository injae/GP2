#pragma once

#ifndef __NETWORK_UTIL_HPP__
#define __NETWORK_UTIL_HPP__

#include <nlohmann/json.hpp>
#include <fmt/format.h>
#include <zmqpp/zmqpp.hpp>
#include <range/v3/all.hpp>

#include <string>

namespace net {
    using namespace nlohmann;
    using namespace ranges;

    // data sisze maximum 30byte if over 30 byte use send large_data
    namespace client {
        void send_data(const json& data , zmqpp::socket& socket){
            zmqpp::message msg;
            msg << data.dump();
            socket.send(msg);
            socket.receive(msg);
        }

        template<typename T>
        void send_large_data(const T& data, zmqpp::socket& socket) {
            for_each(data | views::chunk(4),[&](auto chunk) {
                zmqpp::message msg;
                json data(chunk | to_vector);
                msg << data.dump();
                socket.send(msg);
                socket.receive(msg);
            });
            zmqpp::message msg;
            msg << "finish";
            socket.send(msg);
            socket.receive(msg);
        }
        json receive_data(zmqpp::socket &socket) {
            json data;
            std::string buf;
            zmqpp::message msg;
            socket.send("get");
            socket.receive(msg);
            msg >> buf;
            data = json::parse(buf);
            return data;
        }
        template<typename T>
        std::vector<T> receive_large_data(zmqpp::socket& socket) {
            std::vector<T> result;
            std::string buf;
            while(true) {
                zmqpp::message msg;
                socket.send("get");
                socket.receive(msg);
                msg >> buf;
                if(buf == "finish") break;
                auto data = json::parse(buf);
                copy(data, back_inserter(result));
            }
            return result;
        }
    }

    namespace server {
        json receive_data(zmqpp::socket &socket) {
            json data;
            std::string buf;
            zmqpp::message msg;
            socket.receive(msg);
            msg >> buf;
            socket.send("ok");
            data = json::parse(buf);
            return data;
        }
        template<typename T>
        std::vector<T> receive_large_data(zmqpp::socket& socket) {
            std::vector<T> result;
            std::string buf;
            while(true) {
                zmqpp::message msg;
                socket.receive(msg);
                msg >> buf;
                socket.send("ok");
                if(buf == "finish") break;
                auto data = json::parse(buf);
                copy(data, back_inserter(result));
            }
            return result;
        }
        void send_data(const json& data , zmqpp::socket& socket){
            zmqpp::message check;
            zmqpp::message msg;
            socket.receive(check);
            msg << data.dump();
            socket.send(msg);
        }

        template<typename T>
        void send_large_data(const T& data, zmqpp::socket& socket) {
            for_each(data | views::chunk(4),[&](auto chunk) {
                zmqpp::message check;
                zmqpp::message msg;
                socket.receive(check);
                json data(chunk | to_vector);
                msg << data.dump();
                socket.send(msg);
            });
            zmqpp::message msg;
            socket.receive(msg);
            socket.send("finish");
        }
        
    }


}

#endif
