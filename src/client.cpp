#include <iostream>
#include <future>
#include <map>

#include <fmt/format.h>
#include <range/v3/all.hpp>
#include <nlohmann/json.hpp>
#include <fmt/ranges.h>

#include <zmqpp/zmqpp.hpp>

#include "db/connector.hpp"
#include "db/migrate.hpp"

#include "secure/psi.hpp"
#include "secure/hash.hpp"

#include "network/util.hpp"
#include "utility/parallel.hpp"

using namespace ranges;
using namespace nlohmann;
using namespace ssl;
using namespace net::client;

int main(int argc, char* argv[]) {
    auto database = db::Connector("_PrivateSetX").setup();
    zmqpp::context context;
    zmqpp::socket socket (context, zmqpp::socket_type::req);
    socket.connect("tcp://localhost:66555");

    //database.drop_table();
    auto X = database.visitor();
    fmt::print("visitors:{}\n",X.size());
    if(X.empty()) {
        //db::migrate(database);
        //X = database.visitor();
        fmt::print(stderr,"database empty\n"); exit(1);
    }

    // c-1
    fmt::print("c-1\n");
    auto keys = psi::setup(1024);
    auto& [p, g0, g1, g2, q] = keys;
    auto HX = X  | par::transform(par::csize(X), [](auto it) { return sha256::hash_to_Bn(it); }) | to_vector;
    auto An = HX | views::transform([&keys](auto it) { return keys.H1(it); });
    auto A = accumulate(An, Bn::one(), [p = p](auto it, auto acc) { return it.mul(acc, p);});

    // c-2
    fmt::print("c-2\n");
    auto r = keys.r();
    auto B = A.mul(g0.exp(r, p), p);

    // c-3~5
    fmt::print("c-3[chunk:{}]\n",distance(An)/(std::thread::hardware_concurrency()*2));
    auto aon = An | par::transform(par::rsize(An), [&](auto Ai) {
            const auto& [p, g0, g1, g2, q] = keys;
            auto Bi = A.mul(Ai.inv(p),p);
            auto ri  = keys.r();
            auto ai = Ai.mul(g1.exp(ri, p), p);
            auto oi = Bi.mul(g2.exp(ri, p), p);
            return std::make_tuple(ai, oi, ri);
    }) | to_vector;


    // c-6
    fmt::print("c-6\n");
    auto [a1, o1, r1] = aon[0];
    auto y = B.mul(a1.mul(o1, p).inv(p), p);
    auto h = g1.mul(g2, p);
    auto pi_c = psi::two_prover(p, g0, h, q, r, r1.negate() , y); // pi2 == pic

    auto an = aon | views::transform([&](auto it){return get<0>(it); });
    auto on = aon | views::transform([&](auto it){return get<1>(it); });
    auto rn = aon | views::transform([&](auto it){return get<2>(it); });

    // c-7 send server keys B, an, on, pi2
    fmt::print("c-7[key]\n");
    send_data(keys, socket);
    fmt::print("c-7[B]\n");
    send_data(B, socket);
    fmt::print("c-7[an]\n");
    send_large_data(an, socket);
    fmt::print("c-7[on]\n");
    send_large_data(on, socket);
    fmt::print("c-7[pi c]\n");
    send_data(pi_c, socket);

    // c-8
    fmt::print("c-8\n");
    //auto [S, bn, Um, pi_s] =  server_to_client;
    Bn S = receive_data(socket);
    auto bn = receive_large_data<Bn>(socket);
    auto Um = receive_large_data<Bn>(socket);
    EqualValue pi_s = receive_data(socket);

    // c-9~10

    fmt::print("c-9\n");
    assert(psi::equal_verifier(pi_s, p, g1, a1, q ,S ,bn[0]));


    fmt::print("c-11\n");
    std::map<Bn, int> Cn_map;
    auto Cn = views::zip(bn, An, HX, rn) | par::transform(par::csize(bn),[&,p=p](auto it){
        auto& [bi, Ai, xi, ri]= it;
        auto ki = bi.mul(S.exp(ri,p).inv(p), p);
        return psi::H({ki, Ai, xi});
    }) | to_vector;

    fmt::print("c-13\n");
    std::vector<int> I;
    for (auto&& [i, ci] : Cn | views::enumerate) { Cn_map.insert({ci, i}); }
    for(auto& uj: Um) {
        if(auto search = Cn_map.find(uj); search != Cn_map.end()) I.emplace_back(search->second);
    }

    fmt::print("intersection[{}]:{}\n", I.size(), I | views::transform([&](auto it) { return X[it]; }));
    fmt::print("finish\n");

    return 0;
}
