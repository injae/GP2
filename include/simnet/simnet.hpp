#pragma once

#ifndef __SIMNET_HPP__
#define __SIMNET_HPP__

#include <iostream>

#include <memory>
#include <utility>
#include <future>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>
#include <asio/streambuf.hpp>
#include <asio/connect.hpp>
#include <fmt/format.h>
#include <simnet/none_block_queue.hpp>
#include <asio/use_future.hpp>

using asio::ip::tcp;
namespace simnet {

    inline std::string make_packet(const std::string& data) { return data + "\r\n";}
    std::string make_string(asio::streambuf& buffer, size_t length) {
        std::string data{asio::buffers_begin(buffer.data()), asio::buffers_begin(buffer.data()) + length};
        buffer.consume(length);
        return data;
    }

    class server;
    class client;

    class session : public std::enable_shared_from_this<session> {
        friend server;
        friend client;
    public:
        using ptr = std::shared_ptr<session>;
        session(tcp::socket socket) : socket_(std::move(socket)) {}
        void send(const std::string& data) {
            auto self(shared_from_this());
            auto body = make_packet(data);
            asio::async_write(socket_, asio::buffer(body), [self](std::error_code ec, std::size_t length) {
                if(ec) { fmt::print(stderr, "Error:{}\n", ec.message()); return; }
            });
        }

        void keep_receive() {
            auto self(shared_from_this());
            asio::async_read_until(socket_, buffer_, "\r\n", [this](auto ec, auto length) {
                if(ec) {
                    fmt::print(stderr, "Error:{}\n", ec.message());
                    return;
                }
                queue_.push(make_string(buffer_, length));
                receive();
            });
        }
        template<typename Func>
        void keep_receive(Func&& func) {
            auto self(shared_from_this());
            asio::async_read_until(socket_, buffer_, "\r\n", [this, func](auto ec, auto length) {
                if(ec == asio::error::operation_aborted) {
                    fmt::print("abort:{}",buffer_.size());
                    fmt::print("abort receiving\n");
                    return;
                }
                if(ec) {
                    fmt::print(stderr, "Error:{}\n", ec.message()); exit(1);
                }
                func(make_string(buffer_, length));
                keep_receive(func);
            });
        }

        std::future<std::string> receive() {
            auto self(shared_from_this());
            return std::async([this](){
                auto length_f= asio::async_read_until(socket_, buffer_, "\r\n", asio::use_future);
                length_f.wait();
                auto msg = make_string(buffer_, length_f.get());
                return msg;
            });
        }

        auto& queue() { return queue_; }
        tcp::socket& socket() { return socket_; }
        asio::streambuf buffer_;
    private:
        tcp::socket socket_;
        std::promise<std::string> promise_;
        simnet::block_queue<std::string> queue_;
    };

    class server {

    public:
        server(asio::io_context& io_context, short port)
            : acceptor_(io_context, tcp::endpoint(asio::ip::address_v4::any(), port)), socket_(io_context) {}
        void accept() {
            //            acceptor_.set_option(asio::socket_base::reuse_address(true));
            acceptor_.async_accept(socket_, [this](auto ec) {
                if(ec) return;
                fmt::print("accpet client {}:", socket_.remote_endpoint().port());
                fmt::print("{}\n", socket_.local_endpoint().port());
                sessions_.push_back(std::make_shared<session>(std::move(socket_)));
                sessions_.back()->receive();
                accept();
            });
        }

        std::vector<std::shared_ptr<session>>& sessions() { return sessions_; }
    private:
        std::vector<std::shared_ptr<session>> sessions_;
        tcp::acceptor acceptor_;
        tcp::socket socket_;
    };

    class client {
    public:
        client(asio::io_context& io_context) : resolver_(io_context) {
            session_ = std::make_shared<session>(tcp::socket(io_context));
        }
        void connect(const std::string& ip, const std::string& port) {
            asio::connect(session_->socket_, resolver_.resolve(ip, port));
            fmt::print("client {}:",session_->socket_.remote_endpoint().port());
            fmt::print("{}\n",session_->socket_.local_endpoint().port());
        }
        std::shared_ptr<session>& api() { return session_; }
    private:
        tcp::resolver resolver_;
        std::shared_ptr<session> session_;
    };
    
}


#endif
