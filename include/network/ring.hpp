#pragma once

#ifndef  __NETWORK_RINGNET_HPP__
#define  __NETWORK_RINGNET_HPP__

#include <simnet/simnet.hpp>

#include <unordered_map>
#include <optional>
#include <nlohmann/json.hpp>
#include <serdepp/utility.hpp>
#include <serdepp/adaptor/nlohmann_json.hpp>
#include <fmt/ranges.h>
#include <optional>
#include "utility/parallel.hpp"

using asio::ip::tcp;

namespace simnet::ring {
    using namespace serde;
    using nlohmann::json;

    struct protocal {
        derive_serde(protocal, ctx.TAG(type).TAG(ip).TAG(port).TAG(data);)
        std::string type; // spread, connect
        std::optional<std::string> ip;
        std::optional<std::string> port;
        std::optional<std::string> data;
        static protocal transfer(const std::string& data) {
            return {
                "transfer",
                std::nullopt,
                std::nullopt,
                data,
            };
        }
        static protocal spread(session::ptr target, const std::string& port, const std::string& sender_port) {
            return {
                "spread",
                target->socket().local_endpoint().address().to_string(),
                port,
                sender_port,
            };
        }
        static protocal connect(session::ptr target, const std::string& port) {
            return {
                "connect",
                target->socket().local_endpoint().address().to_string(),
                port
            };
        }
        static protocal config(const std::string& state = "done") {
            return {
                "config",
                std::nullopt,
                std::nullopt,
                state
            };
        }
        protocal change(const std::string& ch_type) const {
            auto result = *this;
            result.type = ch_type;
            return result;
        }

    };

    class Node {
    public:
        Node(const std::string& port, std::optional<std::string> head = std::nullopt)
            : port_(port)
            , socket_(io_context_)
            , resolver_(io_context_)
            , acceptor_(io_context_, tcp::endpoint(tcp::v4(), std::stoi(port_)))
        {
            head_ = head ? head : port;
            next_ = head_;
        }
        void send_protocol(protocal proto, const std::string& target) {
            //fmt::print("send:{}\n",target, proto);
            if(proto.type == "spread") proto.data = port_;
            sessions_[target]->send(deserialize<json>(proto).dump());
        }

        void receive_protocol(const protocal& proto, std::shared_ptr<session> session) {
            //fmt::print("receive:{}\n" ,proto);
            if(proto.type == "connect") {
                if(sessions_.find(*proto.port) == sessions_.end()) { // new session
                    sessions_.insert({*proto.port, session}); 
                } 
                if(is_head(port_)) {
                    if(is_head(*next_)) { next_ = proto.port; prev_ = proto.port; }
                    else {
                        prev_ = proto.port;
                        send_protocol(proto.change("spread"), *next_);
                    }
                } 
            }else if(proto.type == "spread") {
                if(not prev_) prev_ = proto.data;
                if (*proto.port == port_) { // is self
                    //fmt::print("finish spread protocal\n");
                    return;
                }
                if(sessions_.find(*proto.port) == sessions_.end()) { // new session
                    connect(*proto.ip, *proto.port);
                    if(next_ == head_) next_ = proto.port;
                    send_protocol(proto, *next_);
                }
            }else if(proto.type == "transfer") {
                session->queue().push(proto.data.value());

            }else if(proto.type == "config") {
                if(*proto.data == "done") {
                    is_configure_mode.store(false);
                    //fmt::print("configure done:{}\n", is_configure());
                }
            }
            else {
                fmt::print(stderr, "unknown protocal\n"); exit(1);
            }
            //fmt::print("info: head:{}, next:{}, port:{}, prev:{}\n",*head_, *next_, port_, *prev_);
        }

        void connect(const std::string& ip, const std::string& port) { // connect other
            auto ses = std::make_shared<session>(tcp::socket(io_context_));
            sessions_.insert({port, ses});
            asio::connect(ses->socket(), resolver_.resolve(ip, port));
            send_protocol(protocal::connect(ses, port_), port);
            keep_receive(ses);
        }

        void regist(const std::string& ip, const std::string& port) { // connect head
            if(port == port_) { fmt::print("this is head\n"); return; }
            connect(ip, port);
        }

        void accept() {
            acceptor_.async_accept(socket_, [this](std::error_code ec) {
                if(ec) { fmt::print("accept finish\n"); return; }
                auto sess = std::make_shared<session>(std::move(socket_));
                auto fdata = sess->receive(); fdata.wait();
                auto json = json::parse(fdata.get());
                auto data = serialize<protocal>(json);
                sessions_[*data.port] = sess;
                receive_protocol(data, sess);
                keep_receive(sess);
                //fmt::print("{}\n",sessions_);
                accept();
            });
        }

        void keep_receive(std::shared_ptr<session> sess) {
            //fmt::print("receive start\n");
            sess->keep_receive([this,sess](auto str){
                auto json = json::parse(str);
                auto data = serialize<protocal>(json);
                receive_protocol(data, sess);
            });
        }

        std::future<std::string> receive_from(const std::string& target) {
            return sessions_[target]->queue().wait_get();
        }

        void send_to(protocal proto, const std::string& target) {
            sessions_[target]->send(deserialize<json>(proto).dump());
        }

        void send_to(const std::string& message, const std::string& target) {
            send_to(protocal::transfer(message), target);
        }

        void send_all(protocal proto) {
            for(auto& [port, session] : sessions_) {
                session->send(deserialize<json>(proto).dump());
            }
        }

        inline void send_all(const std::string& message) {
            send_all(protocal::transfer(message));
        }

        std::vector<std::thread> configure(const std::string& ip, const std::string& port) {
            std::vector<std::thread> pool;
            accept();
            regist(ip, port);
            pool.push_back(run());
            pool.push_back(run());

            return pool;
        }

        void configure_finish() {
            fmt::print("configure mode finished\n");
            if(is_configure_mode.load())  is_configure_mode.store(false);
            for(auto &[port, session] : sessions_) {
                session->socket().cancel();
            }
        }

        void disconnect_all() {
            for(auto &[port, session] : sessions_) {
                session->socket().close();
            }
        }

        bool is_configure() {
            return is_configure_mode.load();
        }

        std::vector<std::future<std::string>> receive_all() {
            std::vector<std::future<std::string>> messages;
            for(auto& [port, sess] : sessions_) {
                messages.push_back(sess->queue().wait_get());
            }
            return messages;
        }

        const std::string& port() const { return port_; }
        const std::string& head() const { return *head_; }
        const std::string& next() const { return *next_; }
        const std::string& prev() const { return *prev_; }
        std::thread run() { return std::thread([this](){ io_context_.run(); }); }
        asio::io_context& io_context() { return io_context_; }
        std::unordered_map<std::string, std::shared_ptr<session>>& sessions() { return sessions_; }
        inline bool is_head() { return port_ == *head_; }
    private:
        inline bool is_head(const std::string& port) { return port == *head_; }
        asio::io_context io_context_;
        std::string port_;
        tcp::socket socket_;
        tcp::resolver resolver_;
        tcp::acceptor acceptor_;
        std::unordered_map<std::string, std::shared_ptr<session>> sessions_;
        std::atomic_bool is_configure_mode = true;
        std::optional<std::string> head_ = std::nullopt;
        std::optional<std::string> next_ = std::nullopt;
        std::optional<std::string> prev_ = std::nullopt;
    };

}

#endif
