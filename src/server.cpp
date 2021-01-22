#include <iostream>
#include <memory>
#include <thread>

#include <fmt/format.h>
#include <fmt/ranges.h>
#include <openssl/sha.h>
#include <nlohmann/json.hpp>
#include <zmqpp/zmqpp.hpp>

#include "secure/hash.hpp"
#include "db/connector.hpp"
#include "db/migrate.hpp"
#include "network/util.hpp"
#include "secure/psi.hpp"
#include "utility/parallel.hpp"

#include <future>

using namespace nlohmann;
using namespace ranges;
using namespace ssl;
using namespace net::server;

int main(int argc, char* argv[]) {
    auto database = db::Connector("_PrivateSetY").setup();

    auto Y = database.visitor();
    fmt::print("visitor:{}\n",Y.size());
    if(Y.empty()) { fmt::print(stderr,"database empty\n"); exit(1); } 

    zmqpp::context context;
    zmqpp::socket socket (context, zmqpp::socket_type::rep);
    socket.bind("tcp://*:66555");

    while(true) {
    // s-2  auto [keys, B, an, on, pi_c]  = client_to_server;
        PublicKeys keys = receive_data(socket);
        auto& [p, g0, g1, g2, q] = keys;
        Bn B = receive_data(socket);
        auto an = receive_large_data<Bn>(socket);
        auto on = receive_large_data<Bn>(socket);
        ProofValue pi_c = receive_data(socket);

    // s-3
        auto y = B.mul(an[0].mul(on[0], p).inv(p), p);
        auto h = g1.mul(g2, p);
        assert(psi::two_verifier(pi_c, p, g0, h, q, y));

        // s-5
        auto rr = keys.r();
        auto S = g1.exp(rr, p);

        // s-7~8
        auto bn = an | par::transform(par::csize(an),[p=p, &rr](auto ai) {return ai.exp(rr, p);}) | to_vector;

        // S-9~11
        auto Um = Y | par::transform(par::csize(Y), [&,p=p](auto it) {
                auto yj = sha256::hash_to_Bn(it);
                auto Sj = keys.H1(yj);
                auto kj = Sj.exp(rr, p);
                return psi::H({kj, Sj, yj});
            }) | to_vector;

        // s-6
        auto pi_s = psi::equal_prover(p, g1, an[0], q, rr, S, bn[0]); // pieq == pis

        //  s-12
        //  server_to_client(S, bn, Um, pi_s );
        fmt::print("s-12[S]\n");
        send_data(S, socket);
        fmt::print("s-12[bn]\n");
        send_large_data(bn, socket);
        fmt::print("s-12[Um]\n");
        send_large_data(Um, socket);
        fmt::print("s-12[pi_s]\n");
        send_data(pi_s, socket);

    }

    return 0;
}
