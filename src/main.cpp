
#include <iostream>
#include "hm_crypt/eig.hpp"
#include <range/v3/all.hpp>
#include <fmt/ranges.h>
#include <set>
#include "hm_crypt/hash.hpp"
#include <asio.hpp>

using namespace hmc;
using namespace ssl;
using namespace ranges;

using namespace fmt::literals;

struct EIG {
    inline static eig::public_key pk;
    eig::secret_key sk;
    std::vector<eig::cipher> Cn; 
    std::vector<std::pair<Bn,Bn>> dn;

    // return yi
    void init () {
        auto xi = eig::random_r(pk.q); // 2 < r < q-2
        sk = eig::secret_key(pk, xi);
        pk.yi = pk.g.exp(xi, pk.p);
    }
};

int main(int argc, char* argv[]) {
    // KG(n, bits)
    fmt::print("start\n");
    EIG::pk = eig::public_key(1024);
    std::vector<EIG> Un;
    int user = 3; 
    std::vector<std::string> Mn{"AA", "BB", "CC"}; //plain text

    fmt::print("step1\n");
    auto& [p, q, g, Y, yi] = EIG::pk;

    // user add and calculate Y
    Y = Bn::one();
    for(int i =0; i < user; ++i) {
        EIG Ui;
        Ui.init();
        Y = Y.mul(Ui.pk.yi, p); // spread and calculate Y
        Un.push_back(Ui);
    }
    for(auto& it : Un) { it.pk.y = Y; }

    for(auto [i, Ui] : Un | views::enumerate) { Un[0].Cn.push_back(Ui.pk.encrypt(Mn[i])); }

    // step 2 3 4 code
    auto step234 = [&Un](int i) -> std::set<eig::cipher> {
        std::set<eig::cipher> _Cn; // ~Cn
        for (auto& [ui, vi] : Un[i].Cn) {
            auto &[p, q, g, y, yi] = Un[i].pk;
            auto ri = eig::random_r(q);
            auto _ui = ui.mul(g.exp(ri,p),p);
            auto _vi = vi.mul(y.exp(ri,p),p);
            _Cn.insert({_ui, _vi}); // _Cn -> ~Cn
        }
        return _Cn;
    };

    fmt::print("step2\n");
    Un[1].Cn = step234(0) | to_vector; 
    
    
    fmt::print("step3\n");
    Un[2].Cn = step234(1) | to_vector;
   
    fmt::print("step4\n");
    {
    Un[2].Cn = step234(2) | to_vector;
    Un[0].Cn = Un[2].Cn; // 
    Un[1].Cn = Un[2].Cn; // 
    }

    // step 5 6 7 code
    auto step567 = [&Un](int i) {
        std::vector<std::pair<Bn, Bn>> dn; // zi, wi
        auto& p = Un[i].pk.p;
        // auto _x = Un[i].sk.x.negate();
        for(auto& [ui, vi] : Un[i].Cn) {
            // auto zi = ui.exp(_x, p);
            auto zi = ui.exp(Un[i].sk.x, p).inv(p);
            auto wi = vi.mul(zi, p);
            dn.emplace_back(zi, wi);
        }
        return dn;
    };

    fmt::print("step5\n");
    Un[0].dn = step567(0);

    fmt::print("step6\n");
    Un[1].dn = step567(1);

    fmt::print("step7\n");
    Un[2].dn = step567(2);

    // print dataset
    fmt::print("Mn:{}\n",Mn);
    fmt::print("pk: p:{}, q:{}, g:{}\n", p, q, g);
    fmt::print("Bn(Mn):{}\n", Mn | views::transform([](auto it){ return Bn(it).to_dec(); }));

    // decrypt 
    for(auto [i, Ui]: Un | views::enumerate) {
        // v * PI(zi)                                                                                 zi
        Bn mi = accumulate(Un, Ui.Cn[i].v, [i=i, p=p](auto it, auto ui) { return it.mul(ui.dn[i].first, p); });
        fmt::print("{}\n",mi.to_dec());
    }

    //    for(int i = 0; i < 3; ++i) {
    //        fmt::print("============================\n");
    //        fmt::print("M{}:{}\n",i,Bn(Mn[i]));
    //        fmt::print("Z1:{}\n",Un[i].dn[0].first);
    //        fmt::print("W1:{}\n",Un[i].dn[0].second);
    //        fmt::print("Z2:{}\n",Un[i].dn[1].first);
    //        fmt::print("W2:{}\n",Un[i].dn[1].second);
    //        fmt::print("Z3:{}\n",Un[i].dn[2].first);
    //        fmt::print("W3:{}\n",Un[i].dn[2].second);
    //    }

    return 0; 
}
